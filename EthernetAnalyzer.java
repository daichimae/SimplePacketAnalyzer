import java.nio.ByteBuffer;

/**
 * Takes an Ethernet packet as a ByteBuffer object and analyze it.
 *
 * @author Daichi Mae
 */
public class EthernetAnalyzer implements PacketAnalyzer {
	
	private int packetSize;
	private int [] destinationMAC = new int[6];
	private int [] sourceMAC = new int[6];
	private int etherType;
	
	
	public EthernetAnalyzer(ByteBuffer bb) {
		readPacket(bb);
	}
	
	@Override
	public void readPacket(ByteBuffer bb) {
		packetSize = bb.remaining();
		
		for(int i = 0; i < destinationMAC.length; i++) { // get 6 bytes
			destinationMAC[i] = bb.get() & 0xFF;
		}

		for(int i = 0; i < sourceMAC.length; i++) { // get 6 bytes
			sourceMAC[i] = bb.get() & 0xFF;
		}
		
		etherType = bb.getShort() & 0xFFFF;
	}
	
	@Override
	public void printHeader() {
		String tag = "ETHER:  ";
		System.out.println(tag + "----- Ether Header -----");
		System.out.println(tag);
		System.out.println(tag + "Packet size = " + packetSize + " bytes");
		System.out.print(tag + "Destination = " + destinationMAC[0]);
		for(int i = 1; i < destinationMAC.length; i++)
			System.out.print(":" + destinationMAC[i]);
		System.out.println();
		System.out.print(tag + "Source      = " + sourceMAC[0]);
		for(int i = 1; i < sourceMAC.length; i++)
			System.out.print(":" + sourceMAC[i]);
		System.out.println();
		System.out.println(tag + "Ethertype = " + String.format("%04x", etherType));
		System.out.println(tag);
	}
}
