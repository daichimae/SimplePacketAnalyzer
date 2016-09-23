import java.nio.ByteBuffer;

/**
 * Takes an IP packet as a ByteBuffer object and analyze it.
 *
 * @author Daichi Mae
 */
public class IpAnalyzer implements PacketAnalyzer {
	private int ipv;
	private int ihl;
	private int typeOfService;
	private int totalLength;
	private int id;
	private int flags;
	private int [] fragments = new int[2]; // 0:DF, 1:MF
	private int fragmentOffset;
	private int ttl;
	private int protocol;
	private int ipChecksum;
	private int [] sourceIP = new int[4];
	private int [] destinationIP = new int[4];
	private int ipOptions;


	public IpAnalyzer(ByteBuffer bb) {
		readPacket(bb);
	}

	@Override
	public void readPacket(ByteBuffer bb) {
		int temp = bb.get() & 0xFF;
		ipv = temp >>> 4; // get the upper 4 bits
		ihl = (temp & 0x0F) * 4; // lower 4 bits
		typeOfService = bb.get() & 0xFF;
		totalLength = bb.getShort() & 0xFFFF;
		id = bb.getShort() & 0xFFFF;
		
		temp = bb.getShort() & 0xFFFF;
		flags = temp >>> 13; // get the upper 3 bits
		fragments[0] = (flags >>> 1) & 1;
		fragments[1] = flags & 1;
		fragmentOffset = temp & 0x1FFF;

		ttl = bb.get() & 0xFF;
		protocol = bb.get() & 0xFF;
		ipChecksum = bb.getShort() & 0xFFFF;
		
		for(int i = 0; i < 4; i++) { // get 4 bytes
			sourceIP[i] = bb.get() & 0xFF;
		}
		
		for(int i = 0; i < 4; i++) { // get 4 bytes
			destinationIP[i] = bb.get() & 0xFF;
		}
		
		if(ihl > 5)
			ipOptions = 0;
		else
			ipOptions = 1;
			// get the option field
	}
	
	@Override
	public void printHeader() {
		String tag = "IP:   ";
		System.out.println(tag + "----- IP Header -----");
		System.out.println(tag);
		System.out.println(tag + "Version = " + ipv);
		System.out.println(tag + "Header length = " + ihl + " bytes");
		System.out.println(tag + "Type of service = 0x" + String.format("%02x", typeOfService));
		System.out.println(tag + "Total length = " + totalLength + " bytes");
		System.out.println(tag + "Identification = " + id);
		System.out.println(tag + "Flags = 0x" + Integer.toHexString(flags));
		System.out.print(tag + "      ." + fragments[0] + ".");
		if(fragments[0] == 1) System.out.println(" = do not fragment");
		else System.out.println(" = fragment");
		System.out.print(tag + "      .." + fragments[0]);
		if(fragments[0] == 1) System.out.println(" = more fragments");
		else System.out.println(" = last fragment");
		System.out.println(tag + "Fragment offset = " + fragmentOffset + " bytes");
		System.out.println(tag + "Time to live = " + ttl + " seconds/hops");
		System.out.println(tag + "Protocol = " + protocol);
		System.out.println(tag + "Header checksum = " + Integer.toHexString(ipChecksum));
		System.out.print(tag + "Source address = " + sourceIP[0]);
		for(int i = 1; i < sourceIP.length; i++)
			System.out.print("." + sourceIP[i]);
		System.out.println();
		System.out.print(tag + "Destination address = " + destinationIP[0]);
		for(int i = 1; i < destinationIP.length; i++)
			System.out.print("." + destinationIP[i]);
		System.out.println();
		if(ipOptions == 0)
			System.out.println(tag + "No options");
		else
			System.out.println(tag + "There are options");
		System.out.println(tag);
	}

    /**
     * Accessor
     * @return protocol number
     */
	public int getProtocol() {
		return protocol;
	}
}