var voltage = 12;           // Voltage in volts
var resistanceLoad1 = 5000;  // Resistance for Load 1 in ohms
var resistanceLoad2 = 1000;  // Resistance for Load 2 in ohms

var currentLoad1_microamps = (voltage / resistanceLoad1) * 1000; // Convert to microamperes
currentLoad1_microamps = parseFloat(currentLoad1_microamps.toFixed(2)); // Round to two decimal places
currentLoad1_microamps = currentLoad1_microamps * 1000

var currentLoad2_microamps = (voltage / resistanceLoad2) * 1000; // Convert to microamperes
currentLoad2_microamps = parseFloat(currentLoad2_microamps.toFixed(2)); // Round to two decimal places
currentLoad2_microamps = currentLoad2_microamps * 1000

var msg1 = { payload: voltage };
var msg2 = { payload: resistanceLoad1 };
var msg3 = { payload: resistanceLoad2 };
var msg4 = { payload: currentLoad1_microamps };
var msg5 = { payload: currentLoad2_microamps };

return [msg1, msg2, msg3, msg4, msg5];
