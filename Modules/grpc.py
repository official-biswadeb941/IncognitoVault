from concurrent import futures
import grpc
from Modules.proto.iv_pb2_grpc import DynamicResponse
from Modules.proto.iv_pb2_grpc import DynamicVaultServiceServicer, add_DynamicVaultServiceServicer_to_server

class DynamicVaultService(DynamicVaultServiceServicer):
    def ExchangeData(self, request, context):
        print(f"Operation: {request.operation}")
        print(f"Metadata: {request.metadata}")
        print(f"Payload: {request.payload.decode('utf-8')}")  # Assuming payload is JSON
        
        # Process the request dynamically based on the operation
        if request.operation == "SYNC":
            # Simulate database sync
            return DynamicResponse(success=True, message="Database synced", data=b"{}")
        elif request.operation == "COMMAND":
            # Simulate command execution
            result = f"Executed command with payload: {request.payload.decode('utf-8')}"
            return DynamicResponse(success=True, message="Command executed", data=result.encode('utf-8'))
        else:
            return DynamicResponse(success=False, message="Unknown operation", data=b"")

    def StreamData(self, request_iterator, context):
        for request in request_iterator:
            print(f"Streaming Operation: {request.operation}")
            yield DynamicResponse(success=True, message="Stream received", data=b"{}")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_DynamicVaultServiceServicer_to_server(DynamicVaultService(), server)
    server.add_insecure_port('[::]:50051')
    print("Dynamic gRPC server running on port 50051")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
