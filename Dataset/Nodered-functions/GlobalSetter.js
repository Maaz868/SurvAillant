var voltage = msg.payload[0];
var resistanceLoad1 = msg.payload[1];
var resistanceLoad2 = msg.payload[2];
var currentLoad1 = msg.payload[3];
var currentLoad2 = msg.payload[4];
var load1 = false;
var load2 = false;

if (resistanceLoad1 === 0 && currentLoad1 === 0 ) {
    resistanceLoad1 = 5000;
    currentLoad1 = 2400;
}

if (resistanceLoad2 === 0 && currentLoad2 === 0) {
    resistanceLoad2 = 1000;
    currentLoad2 = 12000;
}


global.set("voltage", voltage);
global.set("R1", resistanceLoad1);
global.set("R2", resistanceLoad2);
global.set("C1", currentLoad1);
global.set("C2", currentLoad2);

var msg1 = { payload: false };
var msg2 = { payload: false };

// Pass the messages to the next node in the flow
return [msg1, msg2];

// return msg;
