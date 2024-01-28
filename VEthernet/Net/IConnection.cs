namespace VEthernet.Net
{
    using System.Net;

    public enum ConnectionState
    {
        Connection,
        Connected,
        Disconnecting,
        Closed,
    }

    public interface IConnection
    {
        ConnectionState State { get; }

        EndPoint Source { get; }

        EndPoint Destination { get; }
    }
}
