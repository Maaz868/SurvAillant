// Accessing global variables
// Accessing global variables
var voltage = global.get("voltage");
var r1 = global.get("R1");
var r2 = global.get("R2");
var c1 = global.get("C1");
var c2 = global.get("C2");

// Accessing control variables from Modbus Read Node
var incLoad1 = msg.payload[0];
var decLoad1 = msg.payload[1];
var incLoad2 = msg.payload[2];
var decLoad2 = msg.payload[3]; 
var closeLoad1 = msg.payload[4]; 
var closeLoad2 = msg.payload[5];
// console.log(closeLoad1)


if (incLoad1 === true) {
    // Increase resistance for Load 1
    // console.log("inc1 true");
    r1 += 100;
}
if (decLoad1 === true) {
    // console.log("dec1 true");
    // Decrease resistance for Load 1
    r1 -= 100;
} 
if (incLoad1 === false && decLoad1 === false) {
    r1 += (Math.random() < 0.5 ? -1 : 1) * 100;
}

// Logic for Load 2
if (incLoad2 === true) {
    // console.log("inc2 true");
    // Increase resistance for Load 2
    r2 += 100;
}
if (decLoad2 === true) {
    // console.log("dec2 true");
    // Decrease resistance for Load 2
    r2 -= 100;
} 
if (incLoad2 === false && decLoad2=== false) {
    r2 += (Math.random() < 0.5 ? -1 : 1) * 50;
}



c1 = (voltage / r1) * 1000; // Convert to microamperes
c1 = parseFloat(c1.toFixed(2)); // Round to two decimal places
c1 = c1 * 1000;

c2 = (voltage / r2) * 1000; // Convert to microamperes
c2 = parseFloat(c2.toFixed(2)); // Round to two decimal places
c2 = c2 * 1000;





global.set("voltage", voltage);
global.set("R1", r1);
global.set("R2", r2);
global.set("C1", c1);
global.set("C2", c2);
// console.log(C1)

var msg1 = { payload: voltage };
var msg2 = { payload: r1 };
var msg3 = { payload: r2 };
var msg4 = { payload: c1 };
var msg5 = { payload: c2 };

// Pass the messages to the next node in the flow
return [msg1, msg2, msg3, msg4, msg5];