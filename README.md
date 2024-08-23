# Tales Of Shadowland - Byte Buffer C#

`@tos/bytebuffer` is a lightweight and efficient library for managing binary data in C#. It provides functionalities for reading, writing, queuing, and pooling buffers, along with support for generic network connectors (TCP, UDP, WebSocket).

## Features

- Efficient binary data manipulation with `ByteBuffer`.
- Buffer aggregation with `QueueBuffer` to reduce header overhead.
- Buffer pooling with `ByteBufferPool` to optimize memory allocation in high-frequency systems.
- Interface for generic network connectors supporting TCP, UDP, and WebSocket.

## Usage Example

Here is a basic example of how to use the API provided by the library for binary buffer manipulation:

```csharp
using Server;

class Program
{
    static void Main()
    {
        // Initializing a ByteBuffer
        ByteBuffer buffer = new ByteBuffer();
        buffer.PutInt32(1234).PutString("Hello, ByteBuffer!");

        int num = buffer.GetInt32();
        string str = buffer.GetString();

        Console.WriteLine(num);  // 1234
        Console.WriteLine(str);  // "Hello, ByteBuffer!"

        // Using ByteBufferPool to manage buffers
        ByteBufferPool pool = new ByteBufferPool();
        ByteBuffer pooledBuffer = ConcurrentByteBufferPool.Acquire();
        pooledBuffer.PutFloat(3.14f);
        ConcurrentByteBufferPool.Release(pooledBuffer);

        // Aggregating buffers with QueueBuffer (if implemented)
        // This would combine multiple ByteBuffers into one larger buffer
    }
}
```


## API

### ByteBuffer
The main class for managing binary data in C#. It provides methods for reading and writing various types of binary data.

- **PutInt32(int value): ByteBuffer**: Inserts a 32-bit integer into the buffer.
- **GetInt32(): int**: Reads a 32-bit integer from the buffer.
- **PutString(string value): ByteBuffer**: Inserts a UTF-8 encoded string into the buffer.
- **GetString(): string**: Reads a UTF-8 encoded string from the buffer.
- **Reset(): void**: Resets the buffer's position for reuse and clears its contents.

### ByteBufferPool
Manages a pool of ByteBuffer instances to avoid frequent memory allocations, optimizing performance in high-load systems.

- **Acquire(): ByteBuffer**: Retrieves a buffer from the pool or creates a new one if necessary.
- **Release(ByteBuffer buffer): void**: Returns a buffer to the pool, making it available for reuse.

### ConcurrentByteBufferPool
A thread-local buffer pool that optimizes the use of ByteBuffer instances in multithreaded environments.

- **Acquire(): ByteBuffer**: Acquires a ByteBuffer from the pool, either locally or from the global pool.
- **Release(ByteBuffer buffer): void**: Releases a buffer to the thread-local pool.
- **Merge(): void**: Merges the local buffer pool back into the global pool.
- **Clear(): ByteBuffer**: Clears the global buffer pool and returns the removed buffers.

### QueueBuffer
Aggregates multiple binary buffers to reduce overhead in packet transmissions.

- **Enqueue(ByteBuffer buffer): void**: Adds a buffer to the queue.
- **Combine(): ByteBuffer**: Combines all enqueued buffers into a single buffer (not implemented in this example but could be added if needed).

## Contribution

Contributions are welcome! If you encounter any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
