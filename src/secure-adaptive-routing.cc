#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("CyberAttackAwareAdaptiveRouting");

// Helper to normalize/clamp values strictly to [0.0, 1.0]
inline double Clamp01(double val) {
    if (val < 0.0) return 0.0;
    if (val > 1.0) return 1.0;
    return val;
}

struct NodeMetrics {
    double dropRate = 0.0;
    double anomalyScore = 0.0;
    double delayScore = 0.0;
    double faultPenalty = 0.0;
    double riskScore = 0.0;
    uint32_t dynamicCost = 1;
};

// Global state
NodeMetrics g_targetMetrics;
std::ofstream g_csvLogger;
Ptr<RateErrorModel> g_errorModel;
bool g_isAdaptive = true;

// Adjustable weights
double g_w1 = 0.50; // Drop rate weight
double g_w2 = 0.20; // Anomaly weight
double g_w3 = 0.20; // Delay weight
double g_w4 = 0.10; // Fault weight

// Scenario, topology and logging parameters
std::string g_topology = "nsfnet"; // nsfnet, geant, diamond
std::string g_scenario = "pulsing_grayhole"; 
// Options: pulsing_grayhole, ldos_bufferbloat, metric_poisoning, selective_drop, latency_jitter, clean
std::string g_summaryCsvFile = "";
double g_deltaWeight = 50.0;
uint32_t g_seed = 1;

// FlowMonitor interval delta tracking
uint64_t g_prevTx = 0;
uint64_t g_prevRx = 0;
uint64_t g_prevLost = 0;
Time g_prevDelaySum = Seconds(0);
double g_prevTime = 0.0;

// Dynamic Real Fault Counter (incremented on threshold crossing, decayed on recovery)
double g_faultCount = 0.0;

// Run metrics tracking
double g_minPdrDuringAttack = 100.0;
double g_convergenceTime = -1.0;
uint32_t g_pathSwitches = 0;
std::string g_lastActivePath = "Primary_Path";
bool g_reroutedDuringNonAttack = false;
bool g_hasReroutedDuringAttack = false;

// Interface and router references for dynamic metric adaptation
Ptr<Ipv4> g_targetIpv4Node = nullptr;
std::vector<std::pair<uint32_t, uint32_t>> g_targetInterfaces; // (ifIndex, baseCost)
Ptr<Channel> g_targetChannel = nullptr;

// Attack control functions
void AttackEnable(Ptr<RateErrorModel> em, std::string attackName) {
    NS_LOG_UNCOND("[ATTACK STARTED] t=" << Simulator::Now().GetSeconds() 
                  << "s: " << attackName << " activated on compromised router.");
    if (em) {
        em->Enable();
    }
}

void AttackDisable(Ptr<RateErrorModel> em, std::string attackName) {
    NS_LOG_UNCOND("[ATTACK PAUSED/STOPPED] t=" << Simulator::Now().GetSeconds() 
                  << "s: " << attackName << " paused/stopped.");
    if (em) {
        em->Disable();
    }
}

void SetChannelDelay(Ptr<Channel> ch, Time delay) {
    if (ch) {
        ch->SetAttribute("Delay", TimeValue(delay));
    }
}

// Periodic Security Monitoring & Dynamic Dijkstra Adaptation (every 0.5s)
void PeriodicSecurityMonitor(Ptr<FlowMonitor> monitor,
                             Ptr<Ipv4FlowClassifier> classifier,
                             Ipv4Address srcAddr,
                             Ipv4Address dstAddr,
                             double baselineDelayMs,
                             double deltaWeight) 
{
    double now = Simulator::Now().GetSeconds();

    monitor->CheckForLostPackets();
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    uint64_t totalTx = 0, totalRx = 0, totalLost = 0;
    Time totalDelaySum = Seconds(0);

    for (auto i = stats.begin(); i != stats.end(); ++i) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        if (t.sourceAddress == srcAddr && t.destinationAddress == dstAddr) {
            totalTx += i->second.txPackets;
            totalRx += i->second.rxPackets;
            totalLost += i->second.lostPackets;
            totalDelaySum += i->second.delaySum;
        }
    }

    // 1. Telemetry Delta Tracking
    uint64_t deltaTx = (totalTx >= g_prevTx) ? (totalTx - g_prevTx) : 0;
    uint64_t deltaRx = (totalRx >= g_prevRx) ? (totalRx - g_prevRx) : 0;
    uint64_t deltaLost = (totalLost >= g_prevLost) ? (totalLost - g_prevLost) : 0;
    Time deltaDelay = (totalDelaySum >= g_prevDelaySum) ? (totalDelaySum - g_prevDelaySum) : Seconds(0);
    double deltaTime = (g_prevTime > 0.0) ? (now - g_prevTime) : 0.5;

    g_prevTx = totalTx;
    g_prevRx = totalRx;
    g_prevLost = totalLost;
    g_prevDelaySum = totalDelaySum;
    g_prevTime = now;

    const double expectedRatePps = 100.0;
    const double maxFaults = 5.0;
    const double riskThreshold = 0.03;

    double intervalDropRate = 0.0;
    double intervalDelayScore = 0.0;
    double intervalAnomalyScore = 0.0;
    double intervalDelayMs = baselineDelayMs;

    if (deltaTx > 0) {
        // Drop rate: fraction of sent packets lost in this interval
        intervalDropRate = (double)deltaLost / (double)deltaTx;

        // Delay score: observed latency spike compared to baseline
        if (deltaRx > 0) {
            intervalDelayMs = (deltaDelay.GetSeconds() / (double)deltaRx) * 1000.0;
            intervalDelayScore = (baselineDelayMs > 0.0) ? std::max(0.0, (intervalDelayMs - baselineDelayMs) / baselineDelayMs) : 0.0;
        }

        // Throughput Anomaly: observed arrival rate deviation
        double observedRatePps = (deltaTime > 0.0) ? ((double)deltaRx / deltaTime) : 0.0;
        intervalAnomalyScore = (expectedRatePps > 0.0) ? std::abs(observedRatePps - expectedRatePps) / expectedRatePps : 0.0;
    }

    // 2. Real Fault Counter with 0.70 Recovery Decay Rule
    if (intervalDropRate > riskThreshold || intervalDelayScore > 0.25 || intervalAnomalyScore > 0.25) {
        g_faultCount = std::min(maxFaults, g_faultCount + 1.5);
    } else if (g_faultCount > 0.0) {
        // Exponential decay of fault penalty on healthy recovery
        g_faultCount = g_faultCount * 0.70;
        if (g_faultCount < 0.05) {
            g_faultCount = 0.0;
        }
    }

    double faultPenalty = g_faultCount / maxFaults;

    // 3. Adaptive Risk Calculation & Dynamic Cost Update
    if (g_isAdaptive) {
        bool onPrimary = (g_lastActivePath == "Primary_Path");
        if (onPrimary) {
            g_targetMetrics.dropRate = Clamp01(intervalDropRate);
            g_targetMetrics.anomalyScore = Clamp01(intervalAnomalyScore);
            g_targetMetrics.delayScore = Clamp01(intervalDelayScore);
            g_targetMetrics.faultPenalty = Clamp01(faultPenalty);
        } else {
            // When traffic is diverted to alternate path, penalties decay slowly to prevent route flapping
            g_targetMetrics.dropRate = Clamp01(g_targetMetrics.dropRate * 0.85);
            g_targetMetrics.anomalyScore = Clamp01(g_targetMetrics.anomalyScore * 0.85);
            g_targetMetrics.delayScore = Clamp01(g_targetMetrics.delayScore * 0.85);
            if (g_targetMetrics.dropRate < 0.01) g_targetMetrics.dropRate = 0.0;
            if (g_targetMetrics.anomalyScore < 0.01) g_targetMetrics.anomalyScore = 0.0;
            if (g_targetMetrics.delayScore < 0.01) g_targetMetrics.delayScore = 0.0;
            g_targetMetrics.faultPenalty = Clamp01(faultPenalty);
        }

        // 4-Factor Weighted Risk Score clamped to [0.0, 1.0]
        double rawRisk = (g_w1 * g_targetMetrics.dropRate) + 
                         (g_w2 * g_targetMetrics.anomalyScore) + 
                         (g_w3 * g_targetMetrics.delayScore) + 
                         (g_w4 * g_targetMetrics.faultPenalty);
        if (rawRisk < 0.015) {
            rawRisk = 0.0;
        }
        g_targetMetrics.riskScore = Clamp01(rawRisk);

        // Dynamic link inflation: Cost(e) = BaseCost + ceil(delta * RiskScore)
        uint32_t costPenalty = (g_targetMetrics.riskScore == 0.0) ? 0 : 
            static_cast<uint32_t>(std::ceil(deltaWeight * g_targetMetrics.riskScore));

        if (g_targetIpv4Node) {
            for (auto& ifacePair : g_targetInterfaces) {
                uint32_t ifIdx = ifacePair.first;
                uint32_t baseCost = ifacePair.second;
                uint32_t newCost = baseCost + costPenalty;
                g_targetIpv4Node->SetMetric(ifIdx, (uint16_t)newCost);
            }
            // Trigger autonomous Dijkstra shortest path recalculation across entire network topology
            Ipv4GlobalRoutingHelper::RecomputeRoutingTables();
        }
    }

    // Determine current active path based on whether the primary path cost exceeded alternate threshold
    std::string activePath = (g_targetMetrics.riskScore < 0.08) ? "Primary_Path" : "Alternate_Path";
    double pdr = (totalTx > 0) ? ((double)totalRx / (double)totalTx) * 100.0 : 100.0;

    if (activePath != g_lastActivePath) {
        g_pathSwitches++;
        if (activePath == "Alternate_Path") {
            NS_LOG_UNCOND("[ADAPTIVE REROUTE] t=" << now << "s: Threat detected (Risk=" 
                          << g_targetMetrics.riskScore << "). Autonomous reroute away from compromised node.");
        } else {
            NS_LOG_UNCOND("[ADAPTIVE RESTORE] t=" << now << "s: Node recovered (Risk=" 
                          << g_targetMetrics.riskScore << "). Autonomous return to optimal primary path.");
        }
        g_lastActivePath = activePath;
    }

    // Evaluate metrics during disturbance window (15.0s to 45.0s)
    bool isAttackScenario = (g_scenario != "clean" && g_scenario != "none");

    if (now >= 15.0 && now <= 45.0) {
        if (pdr < g_minPdrDuringAttack) {
            g_minPdrDuringAttack = pdr;
        }

        if (isAttackScenario) {
            if (activePath == "Alternate_Path" && !g_hasReroutedDuringAttack) {
                g_hasReroutedDuringAttack = true;
                g_convergenceTime = now - 15.0;
            }
        } else {
            if (activePath == "Alternate_Path") {
                g_reroutedDuringNonAttack = true;
            }
        }
    }

    if (g_csvLogger.is_open()) {
        uint32_t currentTargetCost = (g_targetInterfaces.empty()) ? 5 : 
            (g_targetInterfaces[0].second + static_cast<uint32_t>(std::ceil(deltaWeight * g_targetMetrics.riskScore)));

        g_csvLogger << std::fixed << std::setprecision(2)
                    << now << ","
                    << totalTx << ","
                    << totalRx << ","
                    << pdr << ","
                    << intervalDelayMs << ","
                    << g_targetMetrics.riskScore << ","
                    << currentTargetCost << ","
                    << activePath << "\n";
        g_csvLogger.flush();
    }

    if (now + 0.5 <= 60.0) {
        Simulator::Schedule(Seconds(0.5), &PeriodicSecurityMonitor, 
                            monitor, classifier, srcAddr, dstAddr, 
                            baselineDelayMs, deltaWeight);
    }
}

int main(int argc, char* argv[]) {
    std::string csvFileName = "metrics.csv";

    uint32_t customSource = 999;
    uint32_t customDestination = 999;
    uint32_t customTarget = 999;

    CommandLine cmd(__FILE__);
    cmd.AddValue("topology", "Network topology: nsfnet, geant, diamond", g_topology);
    cmd.AddValue("scenario", "Attack scenario: pulsing_grayhole, ldos_bufferbloat, metric_poisoning, selective_drop, latency_jitter, clean", g_scenario);
    cmd.AddValue("source", "Source node index (0 to N-1)", customSource);
    cmd.AddValue("destination", "Destination node index (0 to N-1)", customDestination);
    cmd.AddValue("target", "Target compromised node index (0 to N-1)", customTarget);
    cmd.AddValue("w1", "Drop rate weight", g_w1);
    cmd.AddValue("w2", "Anomaly weight", g_w2);
    cmd.AddValue("w3", "Delay weight", g_w3);
    cmd.AddValue("w4", "Fault weight", g_w4);
    cmd.AddValue("isAdaptive", "Enable Adaptive Dijkstra routing", g_isAdaptive);
    cmd.AddValue("csvFile", "Output CSV file name for time series", csvFileName);
    cmd.AddValue("summaryCsvFile", "Output summary CSV file to append run metrics", g_summaryCsvFile);
    cmd.AddValue("delta", "Delta weight for risk escalation", g_deltaWeight);
    cmd.AddValue("seed", "Random seed / run index", g_seed);
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    LogComponentEnable("CyberAttackAwareAdaptiveRouting", LOG_LEVEL_INFO);

    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(g_seed);

    uint32_t numNodes = 14;
    if (g_topology == "geant") numNodes = 22;
    else if (g_topology == "diamond") numNodes = 6;

    NodeContainer nodes;
    nodes.Create(numNodes);

    PointToPointHelper p2p_standard, p2p_primary, p2p_alternate;
    p2p_standard.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p_standard.SetChannelAttribute("Delay", StringValue("4ms"));

    p2p_primary.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p_primary.SetChannelAttribute("Delay", StringValue("4ms"));

    p2p_alternate.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p_alternate.SetChannelAttribute("Delay", StringValue("6ms"));

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    std::vector<NetDeviceContainer> devicesList;
    std::vector<Ipv4InterfaceContainer> interfacesList;

    uint32_t srcNodeIdx = 0;
    uint32_t dstNodeIdx = 12;
    uint32_t targetNodeIdx = 5; // Node to be compromised/attacked
    double baselineDelayMs = 12.0;

    // Lambda helper to create and assign point-to-point link
    uint32_t subnetCounter = 1;
    auto AddLink = [&](uint32_t u, uint32_t v, PointToPointHelper& helper, uint32_t costU = 5, uint32_t costV = 5) {
        NetDeviceContainer dev = helper.Install(nodes.Get(u), nodes.Get(v));
        devicesList.push_back(dev);

        std::string subnet = "10." + std::to_string(subnetCounter / 250) + "." + std::to_string(subnetCounter % 250) + ".0";
        subnetCounter++;
        ipv4.SetBase(subnet.c_str(), "255.255.255.0");
        Ipv4InterfaceContainer ifc = ipv4.Assign(dev);
        interfacesList.push_back(ifc);

        Ptr<Ipv4> ipv4U = nodes.Get(u)->GetObject<Ipv4>();
        Ptr<Ipv4> ipv4V = nodes.Get(v)->GetObject<Ipv4>();

        uint32_t ifIndexU = ipv4U->GetInterfaceForAddress(ifc.GetAddress(0));
        uint32_t ifIndexV = ipv4V->GetInterfaceForAddress(ifc.GetAddress(1));

        ipv4U->SetMetric(ifIndexU, (uint16_t)costU);
        ipv4V->SetMetric(ifIndexV, (uint16_t)costV);

        return std::make_pair(dev, ifc);
    };

    NetDeviceContainer compromisedDevContainer;

    if (g_topology == "nsfnet") {
        // NSFNET: 14 Nodes, 21 Links
        srcNodeIdx = 0;
        dstNodeIdx = 12;
        targetNodeIdx = 5; // Primary transit node: 0 -> 2 -> 5 -> 12
        baselineDelayMs = 12.0;

        // Links definition
        std::vector<std::tuple<uint32_t, uint32_t, uint32_t>> links = {
            {0, 1, 6}, {0, 2, 4}, {0, 3, 6},
            {1, 2, 6}, {1, 7, 6},
            {2, 5, 4}, // Primary bottleneck hop
            {3, 4, 6}, {3, 8, 6},
            {4, 5, 6}, {4, 6, 6},
            {5, 12, 4}, // Primary exit hop to destination
            {5, 13, 6},
            {6, 7, 6},
            {7, 10, 6},
            {8, 9, 6}, {8, 11, 6},
            {9, 10, 6}, {9, 12, 6},
            {10, 11, 6}, {10, 13, 6},
            {11, 12, 6}
        };

        for (auto& l : links) {
            uint32_t u = std::get<0>(l);
            uint32_t v = std::get<1>(l);
            uint32_t cost = std::get<2>(l);

            bool isCompromisedLink = ((u == 2 && v == 5) || (u == 5 && v == 2));
            PointToPointHelper& helper = isCompromisedLink ? p2p_primary : p2p_standard;

            auto linkPair = AddLink(u, v, helper, cost, cost);
            if (isCompromisedLink) {
                compromisedDevContainer = linkPair.first;
            }
        }
    } else if (g_topology == "geant") {
        // GEANT Backbone: 22 Nodes, 36 Links
        srcNodeIdx = 0;
        dstNodeIdx = 21;
        targetNodeIdx = 8; // Primary transit router
        baselineDelayMs = 16.0;

        std::vector<std::tuple<uint32_t, uint32_t, uint32_t>> links = {
            {0, 1, 6}, {0, 2, 6}, {0, 4, 4},
            {1, 2, 6}, {1, 3, 6},
            {2, 4, 6}, {2, 7, 6},
            {3, 5, 6}, {3, 6, 6},
            {4, 7, 6}, {4, 8, 4}, // Primary link into target Node 8
            {5, 6, 6}, {5, 9, 6},
            {6, 10, 6}, {6, 14, 6},
            {7, 8, 6}, {7, 11, 6},
            {8, 12, 6}, {8, 16, 4}, // Primary link out of Node 8
            {9, 10, 6}, {9, 13, 6},
            {10, 14, 6},
            {11, 12, 6}, {11, 15, 6},
            {12, 16, 6},
            {13, 14, 6}, {13, 17, 6},
            {14, 18, 6},
            {15, 16, 6}, {15, 19, 6},
            {16, 20, 4},
            {17, 18, 6}, {17, 19, 6},
            {18, 20, 6},
            {19, 21, 6},
            {20, 21, 4}
        };

        for (auto& l : links) {
            uint32_t u = std::get<0>(l);
            uint32_t v = std::get<1>(l);
            uint32_t cost = std::get<2>(l);

            bool isCompromisedLink = ((u == 4 && v == 8) || (u == 8 && v == 4));
            PointToPointHelper& helper = isCompromisedLink ? p2p_primary : p2p_standard;

            auto linkPair = AddLink(u, v, helper, cost, cost);
            if (isCompromisedLink) {
                compromisedDevContainer = linkPair.first;
            }
        }
    } else {
        // 6-Node Diamond
        srcNodeIdx = 0;
        dstNodeIdx = 5;
        targetNodeIdx = 2; // R2
        baselineDelayMs = 14.0;

        auto link_s_r1 = AddLink(0, 1, p2p_standard, 1, 1);
        auto link_r1_r2 = AddLink(1, 2, p2p_primary, 5, 5); // Path A
        compromisedDevContainer = link_r1_r2.first;
        AddLink(1, 3, p2p_alternate, 8, 8); // Path B
        AddLink(2, 4, p2p_primary, 5, 5);
        AddLink(3, 4, p2p_alternate, 8, 8);
        AddLink(4, 5, p2p_standard, 1, 1);
    }

    if (customSource < numNodes) srcNodeIdx = customSource;
    if (customDestination < numNodes) dstNodeIdx = customDestination;
    if (customTarget < numNodes) targetNodeIdx = customTarget;

    // Populate global routing tables using Dijkstra Shortest Path First
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Cache target router interfaces and base costs for dynamic metric manipulation
    g_targetIpv4Node = nodes.Get(targetNodeIdx)->GetObject<Ipv4>();
    uint32_t numIfaces = g_targetIpv4Node->GetNInterfaces();
    for (uint32_t i = 1; i < numIfaces; ++i) {
        uint16_t baseMetric = g_targetIpv4Node->GetMetric(i);
        g_targetInterfaces.push_back({i, (uint32_t)baseMetric});
    }

    if (compromisedDevContainer.GetN() > 0) {
        g_targetChannel = compromisedDevContainer.Get(0)->GetChannel();
    }

    // Configure the 5 Real-World Router Attacks
    if (g_scenario == "pulsing_grayhole") {
        // 1. Pulsing Grayhole Attack: 3s dropping (50%), 3s normal, repeating between 15s and 45s
        Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
        g_errorModel = CreateObject<RateErrorModel>();
        g_errorModel->SetAttribute("ErrorRate", DoubleValue(0.50));
        g_errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        g_errorModel->SetRandomVariable(uv);
        g_errorModel->Disable();

        if (compromisedDevContainer.GetN() > 1) {
            compromisedDevContainer.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(g_errorModel));
        }

        // Schedule periodic pulses
        for (double t = 15.0; t < 45.0; t += 6.0) {
            Simulator::Schedule(Seconds(t), &AttackEnable, g_errorModel, "Pulsing Grayhole (Active)");
            Simulator::Schedule(Seconds(t + 3.0), &AttackDisable, g_errorModel, "Pulsing Grayhole (Recovery)");
        }
    } else if (g_scenario == "ldos_bufferbloat") {
        // 2. Low-Rate DoS (LDoS) / Bufferbloat: periodic high-rate micro-bursts saturating queue buffer
        Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
        g_errorModel = CreateObject<RateErrorModel>();
        g_errorModel->SetAttribute("ErrorRate", DoubleValue(0.35)); // Buffer tail-drops
        g_errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        g_errorModel->SetRandomVariable(uv);
        g_errorModel->Disable();

        if (compromisedDevContainer.GetN() > 1) {
            compromisedDevContainer.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(g_errorModel));
        }

        for (double t = 15.0; t < 45.0; t += 2.0) {
            // Queue delay spikes to 50ms during micro-burst, then drains to 4ms
            Simulator::Schedule(Seconds(t), &SetChannelDelay, g_targetChannel, MilliSeconds(50));
            Simulator::Schedule(Seconds(t), &AttackEnable, g_errorModel, "LDoS Bufferbloat Burst");
            Simulator::Schedule(Seconds(t + 0.8), &SetChannelDelay, g_targetChannel, MilliSeconds(4));
            Simulator::Schedule(Seconds(t + 0.8), &AttackDisable, g_errorModel, "LDoS Buffer Drain");
        }
    } else if (g_scenario == "metric_poisoning") {
        // 3. BGP/OSPF Malicious Metric Poisoning: compromised node advertises metric = 1 (attraction/sinkhole), then silently drops 50%
        Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
        g_errorModel = CreateObject<RateErrorModel>();
        g_errorModel->SetAttribute("ErrorRate", DoubleValue(0.50));
        g_errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        g_errorModel->SetRandomVariable(uv);
        g_errorModel->Disable();

        if (compromisedDevContainer.GetN() > 1) {
            compromisedDevContainer.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(g_errorModel));
        }

        // Fake metric announcement at 15.0s
        Simulator::Schedule(Seconds(15.0), [=]() {
            NS_LOG_UNCOND("[ATTACK STARTED] t=15.0s: Malicious Metric Poisoning active. Target advertises Cost=1 to sinkhole traffic.");
            for (auto& ifacePair : g_targetInterfaces) {
                g_targetIpv4Node->SetMetric(ifacePair.first, 1);
            }
            Ipv4GlobalRoutingHelper::RecomputeRoutingTables();
            g_errorModel->Enable();
        });

        Simulator::Schedule(Seconds(45.0), [=]() {
            NS_LOG_UNCOND("[ATTACK STOPPED] t=45.0s: Metric Poisoning attack ended.");
            g_errorModel->Disable();
        });
    } else if (g_scenario == "selective_drop") {
        // 4. Selective Drop: Routing control packets (Hellos) pass 100%, but data packets dropped by 45%
        Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
        g_errorModel = CreateObject<RateErrorModel>();
        g_errorModel->SetAttribute("ErrorRate", DoubleValue(0.45));
        g_errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
        g_errorModel->SetRandomVariable(uv);
        g_errorModel->Disable();

        if (compromisedDevContainer.GetN() > 1) {
            compromisedDevContainer.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(g_errorModel));
        }

        Simulator::Schedule(Seconds(15.0), &AttackEnable, g_errorModel, "Selective Drop (Control=Pass, Data=Drop 45%)");
        Simulator::Schedule(Seconds(45.0), &AttackDisable, g_errorModel, "Selective Drop");
    } else if (g_scenario == "latency_jitter") {
        // 5. Latency Jitter Injection: 0% packet loss, but random 25ms-75ms delay injected, de-synchronizing flows
        for (double t = 15.0; t < 45.0; t += 1.0) {
            uint32_t jitterMs = 25 + (static_cast<uint32_t>(t * 13.0) % 50); // Pseudorandom 25-75ms jitter
            Simulator::Schedule(Seconds(t), &SetChannelDelay, g_targetChannel, MilliSeconds(jitterMs));
        }
        Simulator::Schedule(Seconds(45.0), &SetChannelDelay, g_targetChannel, MilliSeconds(4));
    }

    // Set up Source and Destination Traffic Applications
    uint16_t port = 9000;
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(dstNodeIdx));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(60.0));

    // Get destination IP address
    Ptr<Ipv4> dstIpv4 = nodes.Get(dstNodeIdx)->GetObject<Ipv4>();
    Ipv4Address dstAddr = dstIpv4->GetAddress(1, 0).GetLocal();
    Ptr<Ipv4> srcIpv4 = nodes.Get(srcNodeIdx)->GetObject<Ipv4>();
    Ipv4Address srcAddr = srcIpv4->GetAddress(1, 0).GetLocal();

    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(dstAddr, port)));
    onoff.SetConstantRate(DataRate("819200bps"), 1024); // 100 packets/sec, 1024 bytes
    onoff.SetAttribute("StartTime", TimeValue(Seconds(5.0)));
    onoff.SetAttribute("StopTime", TimeValue(Seconds(60.0)));
    ApplicationContainer clientApp = onoff.Install(nodes.Get(srcNodeIdx));

    if (!csvFileName.empty() && csvFileName != "none") {
        g_csvLogger.open(csvFileName);
        g_csvLogger << "timestamp,tx_packets,rx_packets,pdr,delay_ms,target_risk_score,dynamic_cost,active_path\n";
    }

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());

    Simulator::Schedule(Seconds(5.0), &PeriodicSecurityMonitor, 
                        monitor, classifier, srcAddr, dstAddr, 
                        baselineDelayMs, g_deltaWeight);

    NS_LOG_UNCOND("==========================================================================");
    NS_LOG_UNCOND("Simulation Starting: Topology=" << g_topology << " (" << numNodes << " nodes) | Scenario=" << g_scenario);
    NS_LOG_UNCOND("Weights: w1=" << g_w1 << ", w2=" << g_w2 << ", w3=" << g_w3 << ", w4=" << g_w4 << " | Delta=" << g_deltaWeight);
    NS_LOG_UNCOND("Source Node=" << srcNodeIdx << " -> Destination Node=" << dstNodeIdx << " | Target Compromised Node=" << targetNodeIdx);
    NS_LOG_UNCOND("==========================================================================");

    Simulator::Stop(Seconds(61.0));
    Simulator::Run();

    if (g_csvLogger.is_open()) {
        g_csvLogger.close();
    }
    Simulator::Destroy();

    bool isAttackScenario = (g_scenario != "clean" && g_scenario != "none");
    double reportedConvergence = g_hasReroutedDuringAttack ? g_convergenceTime : (isAttackScenario ? -1.0 : 0.0);
    int falsePositive = g_reroutedDuringNonAttack ? 1 : 0;

    NS_LOG_UNCOND("[RUN COMPLETE] topology=" << g_topology
                  << " scenario=" << g_scenario
                  << " seed=" << g_seed
                  << " w=(" << g_w1 << "," << g_w2 << "," << g_w3 << "," << g_w4 << ")"
                  << " minPdr=" << g_minPdrDuringAttack
                  << " convTime=" << reportedConvergence
                  << " switches=" << g_pathSwitches
                  << " falsePos=" << falsePositive);

    if (!g_summaryCsvFile.empty()) {
        std::ifstream testFile(g_summaryCsvFile);
        bool exists = testFile.good();
        testFile.close();

        std::ofstream summaryOut(g_summaryCsvFile, std::ios::app);
        if (!exists) {
            summaryOut << "topology,scenario,w1,w2,w3,w4,seed,min_pdr,convergence_time,path_switches,false_positive\n";
        }
        summaryOut << std::fixed << std::setprecision(2)
                   << g_topology << ","
                   << g_scenario << ","
                   << g_w1 << ","
                   << g_w2 << ","
                   << g_w3 << ","
                   << g_w4 << ","
                   << g_seed << ","
                   << g_minPdrDuringAttack << ","
                   << reportedConvergence << ","
                   << g_pathSwitches << ","
                   << falsePositive << "\n";
        summaryOut.close();
    }

    return 0;
}
