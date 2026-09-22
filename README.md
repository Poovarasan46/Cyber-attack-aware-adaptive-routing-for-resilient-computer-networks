# 🛡️ Cyber-Attack Aware Adaptive Routing for Resilient Computer Networks

> An autonomic, closed-loop discrete-event network resilience framework implemented in **ns-3 (Network Simulator 3)** that detects adversarial intermediate node degradation in real time and dynamically recalculates Dijkstra link metrics to maintain high-availability data delivery.

---

## 📖 1. Project Information & Theoretical Background

### 1.1 Problem Statement
Conventional Interior Gateway Routing Protocols (e.g., OSPF, IS-IS) rely on static metric formulations (typically based on static link bandwidth or propagation delay). In modern threat landscapes:
* **Grayhole & Selective-Forwarding Attacks:** Adversarial routers silently drop a fraction of data packets while keeping physical link states `UP` and standard Hello/Keepalive exchanges active.
* **Failure of Static Dijkstra:** Because physical topology changes are absent, traditional shortest path first (SPF) algorithms remain locked on degraded paths, causing severe packet loss and service degradation without triggering conventional link-failover mechanisms.

### 1.2 Proposed Solution
This project introduces a **Closed-Loop Adaptive Security Routing Engine** that continuously samples flow-level metrics, computes a 4-dimensional risk score, and programmatically perturbs link routing costs. When risk metrics exceed dynamic thresholds, the engine invokes global routing table recomputation (`Ipv4GlobalRoutingHelper`), seamlessly shifting active flows to resilient alternate paths in sub-second timeframes.

---

### 1.3 Key Features & Mathematical Formulation

#### 🧮 4-Factor Weighted Risk Scoring Model
The monitoring engine samples flow states at 0.5-second periodic intervals using ns-3's `FlowMonitor` and evaluates path health according to:

$$\text{RiskScore}(t) = (w_1 \cdot \text{DropRate}) + (w_2 \cdot \text{AnomalyScore}) + (w_3 \cdot \text{DelayScore}) + (w_4 \cdot \text{FaultPenalty})$$

* **Weight Distribution:**
  * $w_1 = 0.50$ (Packet Drop Rate Weight)
  * $w_2 = 0.20$ (Traffic Pattern Anomaly Weight)
  * $w_3 = 0.20$ (End-to-End Latency Anomaly Weight)
  * $w_4 = 0.10$ (Historical Fault Penalty Weight)

#### ⚙️ Dynamic Link Cost Transformation
When risk is detected on link $i$, its operational routing metric is dynamically adjusted:

$$\text{Cost}_i(t) = \text{BaseCost}_i + \left\lceil \Delta \times \text{RiskScore}(t) \right\rceil$$

* Where $\Delta = 50.0$ represents the penalty sensitivity scaling factor.
* When the attack ceases, exponential metric decay is applied ($\times 0.70$ decay factor per interval) to smoothly restore optimal low-cost primary paths once stability is re-established.

---

### 1.4 Benchmark & Experimental Results

Evaluated across continuous **60-second simulation trials** with continuous **819.2 kbps UDP CBR traffic** under an active **40% malicious packet-drop attack** active from $t = 15.0\text{s}$ to $t = 40.0\text{s}$:

| Metric Parameter | Baseline Static Dijkstra | Proposed Cyber-Aware Adaptive Routing | Improvement / Impact |
| :--- | :---: | :---: | :---: |
| **Minimum PDR during Attack** | **74.32%** | **99.60% – 99.80%** | **+25.48% higher packet delivery** |
| **Total Packet Loss** | Up to **25.68%** | **< 0.40%** | **> 98% reduction in dropped packets** |
| **Path Convergence Time** | N/A (Locked in failure) | **0.85 seconds (< 1.0s)** | **Sub-second autonomic recovery** |
| **End-to-End Delay (Attacked Path)** | 14.00 ms – 17.37 ms | 20.00 ms – 21.55 ms (Safe Reroute) | Stable delivery across backup path |
| **Post-Attack Restoration** | No dynamic awareness | Automatic restoration to Path A | Full state recovery |

---

## 🏛️ 2. System Architecture

```
+-----------------------------------------------------------------------------------+
|                        1. TELEMETRY & PRESENTATION LAYER                          |
|  - Real-Time WebSocket Telemetry Server (FastAPI / Starlette / Uvicorn)           |
|  - Interactive Dashboard UI (Jinja2 Templates / HTML5 Canvas / Chart.js)          |
|  - Offline Matplotlib Sensitivity Analysis & Parameter Sweeps (plot_comparison.py)|
+------------------------------------------^----------------------------------------+
                                           | Telemetry Feed (0.5s sampling)
+------------------------------------------v----------------------------------------+
|                        2. ADAPTIVE CONTROL PLANE                                  |
|  - Dynamic Link Cost Calculation: Cost_A = BaseCost_A + ceil(delta * RiskScore)   |
|  - Global Routing Table Recomputation: Ipv4GlobalRoutingHelper::RecomputeTables()  |
|  - Sub-Second Convergence & Hysteresis Smoothing Engine                           |
+------------------------------------------^----------------------------------------+
                                           | Computed Risk Vectors
+------------------------------------------v----------------------------------------+
|                        3. SECURITY MONITORING ENGINE                              |
|  - ns-3 FlowMonitor & Ipv4FlowClassifier telemetry capture                       |
|  - 4-Factor Anomaly & Packet Loss Scoring Processor                               |
+------------------------------------------^----------------------------------------+
                                           | Packet Telemetry
+------------------------------------------v----------------------------------------+
|                        4. DATA PLANE & NETWORK TOPOLOGY                           |
|  - 6-Node Dual-Path Diamond Topology (PointToPoint 10 Mbps Links)                  |
|  - Continuous CBR UDP Application Layer (1024-byte packets @ 819.2 kbps)          |
|  - RateErrorModel Adversarial Injection Engine (Simulated 40% Drop Attack on R2)  |
+-----------------------------------------------------------------------------------+
```

### 2.1 Topology & Interface Specifications

```
             [ 10.0.2.0/24 ]           [ 10.0.4.0/24 ]
           +-----------------> Router R2 ----------------+
           |                  (Path A: Primary)          |
           |                   Base Cost = 5             |
           |                  Delay = 5ms (10Mbps)       |
           |                  [⚠️ Attack Window: 15-40s] |
           |                  [ 40% Packet Drop Rate   ] |
           |                                             v
[ Source S ] --------> Router R1 -----------------------------> Router R4 --------> [ Destination D ]
 (Node 0)   10.0.1.0/24 (Node 1)                          (Node 4)   10.0.6.0/24  (Node 5)
 10.0.1.1    (Access)   (Ingress)                         (Egress)    (Access)     10.0.6.2
           |                                             ^
           |                  [ 10.0.3.0/24 ]            |
           +-----------------> Router R3 ----------------+
                              (Path B: Backup)
                               Base Cost = 8
                              Delay = 8ms (10Mbps)
                             [ 10.0.5.0/24 ]
```

* **Node 0 (Traffic Source):** IP `10.0.1.1` — Hosts `OnOffApplication` generating constant bit rate UDP traffic.
* **Node 1 (Ingress Router R1):** Dynamically calculates cost metrics between interface to R2 and interface to R3.
* **Node 2 (Primary Router R2 - Path A):** Propagation delay $5\text{ ms}$, Base Metric $= 5$. Houses the adversarial `RateErrorModel`.
* **Node 3 (Backup Router R3 - Path B):** Propagation delay $8\text{ ms}$, Base Metric $= 8$. Safe alternate route.
* **Node 4 (Egress Router R4):** Merges incoming traffic streams and forwards toward destination.
* **Node 5 (Destination Sink D):** IP `10.0.6.2` — Hosts `PacketSink` verifying packet sequence, delay, and delivery.

---

## 🖼️ 3. Architecture & Dashboard Image Section

### 3.1 High-Definition System Architecture
> Visual overview of the multi-layer control loop, security monitoring engine, and the 6-node diamond data plane.

<img width="1376" height="768" alt="architecure" src="https://github.com/user-attachments/assets/7b40c2ec-59f5-4793-8653-52a002cd8d27" />

---

### 3.2 Real-Time Telemetry Web Dashboard
> Live web-based monitoring console streaming real-time network health metrics, instantaneous Packet Delivery Ratio (PDR), latency trends, and automated path failover events.

<img width="1896" height="903" alt="screen1" src="https://github.com/user-attachments/assets/627fb137-492e-4280-8a96-ba354ab09d3a" />
<img width="1895" height="908" alt="screen2" src="https://github.com/user-attachments/assets/6df8a298-cac2-4673-8ac7-1927d4c7f70c" />
<img width="1901" height="907" alt="screen3" src="https://github.com/user-attachments/assets/13429c41-653a-412f-9108-8b9697e3cfd5" />

---

### 3.3 Empirical Benchmark Comparison Charts
> 60-second comparative simulation results showing Packet Delivery Ratio (PDR) stability, latency transitions, and dynamic link metric adaptation during the active attack window ($t=15\text{s}–40\text{s}$).

<img width="1807" height="885" alt="screen4" src="https://github.com/user-attachments/assets/bb22055b-6efa-4838-b4f7-7abad1f4ea37" />

---

## 🛠️ 4. Tech Stack & Tools

* **Core Simulator:** ns-3 (v3.43) / C++17
* **Traffic & Telemetry:** `ns3::FlowMonitor`, `ns3::OnOffApplication`, `ns3::PacketSink`, `ns3::RateErrorModel`
* **Real-Time Backend:** Python 3.10+, FastAPI, Starlette WebSockets, Uvicorn
* **Data Science & Plotting:** Pandas, NumPy, Matplotlib
* **Front-End Telemetry UI:** HTML5, CSS3, JavaScript, Chart.js
