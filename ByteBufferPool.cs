namespace Server
{
    public class ByteBufferPool
    {
        private ByteBuffer head = null;
        private ByteBuffer tail = null;

        public void Add(ByteBuffer buffer)
        {
            buffer.Next = head;

            if (tail == null)
            {
                tail = buffer;
            }

            head = buffer;
        }

        public ByteBuffer Clear()
        {
            ByteBuffer result = head;

            head = null;
            tail = null;

            return result;
        }

        public ByteBuffer Take()
        {
            if (head == null)
                return null;

            ByteBuffer result = head;

            if (head == tail)
            {
                head = null;
                tail = null;
            }
            else
            {
                head = head.Next;
            }

            result.Next = null;
            return result;
        }

        public void Merge(ByteBufferPool other)
        {
            if (head == null)
            {
                head = other.head;
                tail = other.tail;
            }
            else if (other.head != null)
            {
                tail.Next = other.head;
                tail = other.tail;
            }

            other.head = null;
            other.tail = null;
        }

        public int Length
        {
            get
            {
                int count = 0;
                ByteBuffer current = head;

                while (current != null)
                {
                    current = current.Next;
                    count++;
                }

                return count;
            }
        }
    }
}