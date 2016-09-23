import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Read an Ethernet packet and display the header fields and the data, if any.
 *
 * @author Daichi Mae
 */
public class pktanalyzer {

	public static void main(String[] args) {

		ByteBuffer bb = getByteBuffer(args[0]);

        EthernetAnalyzer ethernetAnalyzer = new EthernetAnalyzer(bb);
        ethernetAnalyzer.printHeader();

        IpAnalyzer ipAnalyzer = new IpAnalyzer(bb);
        ipAnalyzer.printHeader();

		if(ipAnalyzer.getProtocol() == 1) {
            IcmpAnalyzer icmpAnalyzer = new IcmpAnalyzer(bb);
            icmpAnalyzer.printHeader();
			System.exit(0);
		}
		else if(ipAnalyzer.getProtocol() == 6) {
            TcpAnalyzer tcpAnalyzer = new TcpAnalyzer(bb);
            tcpAnalyzer.printHeader();
			tcpAnalyzer.printData();
		}
		else if(ipAnalyzer.getProtocol() == 17) {
			UdpAnalyzer udpAnalyzer = new UdpAnalyzer(bb);
            udpAnalyzer.printHeader();
			udpAnalyzer.printData();
		}
		else {
			System.out.println("Can't handle this type of packets.");
		}
	} // end main
	
	/**
	 * Create a ByteBuffer object from a packet file.
	 * 
	 * @param filename
	 * @return ByteBuffer object
	 */
	public static ByteBuffer getByteBuffer(String filename) {
		File file = new File(filename);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		byte [] arr = new byte[(int)file.length()];
		try {
			fis.read(arr);
			fis.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		//  create a byte buffer and wrap the array
		return ByteBuffer.wrap(arr);
	}
} // end pktanalyzer
