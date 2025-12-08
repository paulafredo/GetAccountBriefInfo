# proto_utils.py
from google.protobuf.message import Message

class ProtobufUtils:
    def decode_protobuf(self, data: bytes, pb_class: type[Message]) -> Message:
        """
        Decode protobuf from raw bytes.
        """
        if isinstance(data, str):
            # If someone passes a hex string, convert to bytes
            data = bytes.fromhex(data)
        msg = pb_class()
        msg.ParseFromString(data)
        return msg

    def encode_protobuf(self, msg: Message) -> bytes:
        """
        Encode protobuf to bytes.
        """
        return msg.SerializeToString()
