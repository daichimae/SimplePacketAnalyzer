import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Takes a TCP packet as a ByteBuffer object and analyze it.
 *
 * @author Daichi Mae
 */
public class TcpAnalyzer implements PacketAnalyzer {

    private int sourcePort;
    private int destinationPort;
    private long sequenceNumber;
    private long ackNumber;
    private int dataOffset;
    private int tcpFlags;
    private int [] tcpControlBits = new int[9]; // 0: FIN, 1: SYN ... 8: NS
    private int windowSize;
    private int tcpChecksum;
    private int urgentPointer;
    private int tcpOptions;

    private int [] data = new int[64];

    public TcpAnalyzer(ByteBuffer bb) {
        readPacket(bb);
        readData(bb);
    }

    @Override
    public void readPacket(ByteBuffer bb) {
        int temp;

        sourcePort = bb.getShort() & 0xFFFF;
        destinationPort = bb.getShort() & 0xFFFF;
        sequenceNumber = bb.getInt() & 0xFFFFFFFFL;
        ackNumber = bb.getInt() & 0xFFFFFFFFL;

        temp = bb.getShort() & 0xFFFF;
        dataOffset = (temp >>> 12) * 4; // get the upper 4 bits
        tcpFlags = temp & 0x1FF;

        for(int i = 0; i < 9; i++) {
            tcpControlBits[i] = (temp >>> i) & 1;
        }

        windowSize = bb.getShort() & 0xFFFF;
        tcpChecksum = bb.getShort() & 0xFFFF;
        urgentPointer = bb.getShort() & 0xFFFF;

        tcpOptions = bb.get() & 0xFF;
        if(tcpOptions == 1) { // skip the option field
            // throw away the option field
            for(int i = 1; i < dataOffset - 20; i++)
                bb.get();
        }
    }

    @Override
    public void printHeader() {
        String tag = "TCP:  ";
        System.out.println(tag + "----- TCP Header -----");
        System.out.println(tag);
        System.out.println(tag + "Source port = " + sourcePort);
        System.out.println(tag + "Destination port = " + destinationPort);
        System.out.println(tag + "Sequence number = " + sequenceNumber);
        System.out.println(tag + "Acknowledgement number = " + ackNumber);
        System.out.println(tag + "Data offset = " + dataOffset + " bytes");
        System.out.println(tag + "Flags = 0x" + Integer.toHexString(tcpFlags));
        System.out.print(tag + "      " + tcpControlBits[8] + " .... .... = ");
        if(tcpControlBits[8] == 0)
            System.out.println("No ECN-nonce concealment protection");
        else
            System.out.println("ECN-nonce concealment protection");

        System.out.print(tag + "      . " + tcpControlBits[7] + "... .... = ");
        if(tcpControlBits[7] == 0)
            System.out.println("No congestion control");
        else
            System.out.println("Congestion control");

        System.out.print(tag + "      . ." + tcpControlBits[6] + ".. .... = ");
        if(tcpControlBits[6] == 0)
            System.out.println("No ECN-Echo");
        else
            System.out.println("ECN-Echo");

        System.out.print(tag + "      . .." + tcpControlBits[5] + ". .... = ");
        if(tcpControlBits[5] == 0)
            System.out.println("No urgent pointer");
        else
            System.out.println("Urgent pointer");

        System.out.print(tag + "      . ..." + tcpControlBits[4] + " .... = ");
        if(tcpControlBits[4] == 0)
            System.out.println("No acknowledgement");
        else
            System.out.println("Acknowledgement");

        System.out.print(tag + "      . .... " + tcpControlBits[3] + "... = ");
        if(tcpControlBits[3] == 0)
            System.out.println("No push");
        else
            System.out.println("Push");

        System.out.print(tag + "      . .... ." + tcpControlBits[2] + ".. = ");
        if(tcpControlBits[2] == 0)
            System.out.println("No reset");
        else
            System.out.println("Reset");

        System.out.print(tag + "      . .... .." + tcpControlBits[1] + ". = ");
        if(tcpControlBits[1] == 0)
            System.out.println("No syn");
        else
            System.out.println("Syn");

        System.out.print(tag + "      . .... ..." + tcpControlBits[0] + " = ");
        if(tcpControlBits[0] == 0)
            System.out.println("No fin");
        else
            System.out.println("Fin");

        System.out.println(tag + "Window = " + windowSize);
        System.out.println(tag + "Checksum = 0x" + Integer.toHexString(tcpChecksum));
        System.out.println(tag + "Urgent pointer = " + urgentPointer);
        System.out.println(tag + "No options"); // skip the option fields for now
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
        String tag = "TCP:  ";
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
