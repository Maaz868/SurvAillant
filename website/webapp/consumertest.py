import json
from channels.testing import ChannelsLiveServerTestCase
from channels.layers import get_channel_layer
from asgiref.testing import ApplicationCommunicator
from django.contrib.auth import get_user_model
from .consumers import DashBoardConsumer, PacketConsumer

class DashboardConsumerTest(ChannelsLiveServerTestCase):
    async def test_dashboard_consumer(self):
        # Connect to the WebSocket
        communicator = ApplicationCommunicator(DashBoardConsumer, {"type": "websocket.connect"})
        connected, subprotocol = await communicator.connect()

        # Assert connection is established
        self.assertTrue(connected)

        # Send a message to the WebSocket
        await communicator.send_json_to({"type": "websocket.receive", "text": "test"})

        # Receive a message from the WebSocket
        response = await communicator.receive_json_from()

        # Assert the response is as expected
        self.assertEqual(response, {"type": "websocket.send", "text": "test"})

        # Disconnect from the WebSocket
        await communicator.disconnect()

class PacketConsumerTest(ChannelsLiveServerTestCase):
    async def test_packet_consumer(self):
        # Connect to the WebSocket
        communicator = ApplicationCommunicator(PacketConsumer, {"type": "websocket.connect"})
        connected, subprotocol = await communicator.connect()

        # Assert connection is established
        self.assertTrue(connected)

        # Send a message to the WebSocket
        await communicator.send_json_to({"type": "websocket.receive", "text": "test"})

        # Receive a message from the WebSocket
        response = await communicator.receive_json_from()

        # Assert the response is as expected
        self.assertEqual(response, {"type": "websocket.send", "text": "test"})

        # Disconnect from the WebSocket
        await communicator.disconnect()
