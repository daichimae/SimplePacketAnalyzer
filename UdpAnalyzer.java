import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Takes a UDP packet as a ByteBuffer object and analyze it.
 *
 * @author Daichi Mae
 */
public class UdpAnalyzer implements PacketAnalyzer{

    private int sourcePort;
    private int destinationPort;
    private int dataLength;
    private int udpChecksum;

    private int [] data = new int[64];

    public UdpAnalyzer(ByteBuffer bb) {
        readPacket(bb);
        readData(bb);
    }

    @Override
    public void readPacket(ByteBuffer bb) {
        sourcePort = bb.getShort() & 0xFFFF;
        destinationPort = bb.getShort() & 0xFFFF;
        dataLength = bb.getShort() & 0xFFFF;
        udpChecksum = bb.getShort() & 0xFFFF;
    }

    @Override
    public void printHeader() {
        String tag = "UDP:  ";
        System.out.println(tag + "----- UDP Header -----");
        System.out.println(tag);
        System.out.println(tag + "Source port = " + sourcePort);
        System.out.println(tag + "Destination port = " + destinationPort);
        System.out.println(tag + "Length = " + dataLength);
        System.out.println(tag + "Checksum = 0x" + Integer.toHexString(udpChecksum));
        System.out.println(tag);
    }

    private void readData(ByteBuffer bb) {
        for(int i = 0; i < data.length; i++) {
            try {
                data[i] = bb.get() & 0xFF;
            } catch (BufferUnderflowException e) {
                break;
            }
        }
    }

    public void printData() {
        String tag = "UDP:  ";
        System.out.println(tag + "Data: (first 64 bytes)");
        int columns = 8; int rows = 4;
        for(int i = 0; i < rows; i++) {
            System.out.print(tag);
            for (int j = 0; j < columns; j++) {
                int index = (columns * i * 2) + (j * 2);
                System.out.print(String.format("%02x%02x ", data[index], data[index + 1]));
            }
            // convert int to ASCII
            System.out.print("   \"");
            for (int j = 0; j < columns * 2; j++) {
                int index = (columns * i * 2) + j;
                if (32 <= data[index] && data[index] <= 126) {
                    System.out.print((char) data[index]);
                } else {
                    System.out.print(".");
                }
            }
            System.out.println("\"");
        }
    }
}
