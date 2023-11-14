# SCADA Intrusion Detection Dataset Generator

This repository contains the code for generating a realistic dataset for SCADA intrusion detection using Node-RED and Ignition.

## Project Overview

The goal of this project is to simulate an electrical grid scenario, capturing dynamic variations in voltage, current, and load resistance. The generated dataset serves as a valuable resource for testing and developing intrusion detection systems in SCADA environments.

## Components

### Node-RED
- `node-red-flow.json` Node-RED flow configuration for simulating the electrical grid.
- `node-red-functions` Node-RED functions for data generation and communication with Ignition.

### Ignition
- `ignition_tagChangeScripts` Ignition tag change scripts for implementing control logic based on the received data.

## Usage

1. Node-RED Setup
   - Import the `node-red-flow.json` into your Node-RED instance.
   - Copy and paste the contents of `node-red-functions.js` into Node-RED function nodes.

2. Ignition Setup
   - Use the tag change scripts in `ignition_tagChangeScripts` to implement control logic in Ignition.
   - Create a Modbus device on Ignition web config.
   - Add addresses of holding registers with starting address '1' and ending address '5' with data type 'INT'.
   - Add addresses of coils with starting address '6' and ending address '11'.
   - Locate the tags in terms of addresses in Ignition's designer launcher.
   - Apply the tag change scripts.

3. Generate Dataset
   - Run the Node-RED flow to simulate the electrical grid and communicate with Ignition.
   - Capture the generated dataset in CSV files and pcap format.

## Requirements

- Node-RED v2.0.0 or later
- Ignition v8.1.0 or later

