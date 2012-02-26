package de.fork.java;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * <p>
 * With this class we can run processes using the intended daemon which is 
 * waiting for TCP connections in a specified port.
 * </p>
 * <p>
 * Receiving the results from the daemon where we can find three kinds of 
 * different fields: stderror, stdout and the return value of the command which was
 * run by the remote daemon. Each field is related to the stderr, stdout and 
 * return code respectively.
 * </p>
 * <p>
 * This class has to retrieve the results from the remote daemon and it offers two 
 * methods wich can be used to retrieve the stderr and stdout in a right way 
 * without having to know about the coding used by the daemon to send us the results. 
 * The user does not have to know about how the daemon sends the data, he or she 
 * will work directly with the strings related to each stream using these methods:
 * {@link TCPForkDaemon#getStdout()} and {@link TCPForkDaemon#getStderr()}.
 * The return code from the command executed by the daemon can be retrieved as the 
 * return parameter from the method {@link TCPForkDaemon#exec(String, String, int)}
 * </p>
 * <p>
 * Instances of this class are mutable. To use them concurrently, clients must surround each
 * method invocation (or invocation sequence) with external synchronization of the clients choosing.
 * </p>
 */
public class TCPForkDaemon {
	private final XmlForkParser parser;
	private final String host;
	private final int port;
	
	
	/**
	 * Default constructor for this {@link TCPForkDaemon} implementation.
	 * 
     * <p> The host name can either be a machine name, such as
     * "<code>java.sun.com</code>", or a textual representation of its
     * IP address. If a literal IP address is supplied, only the
     * validity of the address format is checked.
     * </p>
     * <p> For <code>host</code> specified in literal IPv6 address,
     * either the form defined in RFC 2732 or the literal IPv6 address
     * format defined in RFC 2373 is accepted. IPv6 scoped addresses are also
     * supported. See <a href="Inet6Address.html#scoped">here</a> for a description of IPv6
     * scoped addresses.
	 * </p>
	 * @param parser instance implemeting {@link XmlForkParser} which knows about what 
	 * codification uses the daemon to send us the results of the command sent to
	 * by the remote daemon by the {@link TCPForkDaemon.#exec(String)} method.
	 * @param host the specified host.
	 * @param port the TCP port where the daemon accepts connections.
	 * 
	 */
	public TCPForkDaemon (final XmlForkParser parser, final String host, final int port) {
		this.parser = parser;
		this.host = host;
		this.port = port;
	}
	
	
	/**
	 * <p>
	 * This method sends commands to a remote daemon using a TCP socket.
	 * We create a new TCP socket every time we send commands.
	 * </p>
	 * <p>
	 * It uses a TCP connection in order to send commands and receive
	 * the results related to that command from the remote daemon. The command's 
	 * result code which was run by the remote daemon can be retrieved from the
	 * return parameter of this method.
	 * </p>
	 * @param  command the command to be executed by the daemon.
	 * @return the executed command's return code.
	 * @throws IOException 
	 * @throws UnknownHostException
	 * @throws SAXException 
	 * @throws SecurityException if a security manager exists
	 */
	public int exec(final String command) throws UnknownHostException, IOException, SAXException {
		PrintWriter out = null;
		Socket socket = null;
		
	/******************************************************************************************/
	/*          Just over 1 TCP connection                                                    */
	/*          COMMAND_LENGTH: Java integer 4 bytes, BIG-ENDIAN (the same as network order)  */
	/*          COMMAND: remote locale character set encoding                                 */
	/*          RESULTS: remote locale character set encoding                                 */
	/*                                                                                        */
	/*              JAVA CLIENT: ------------ COMMAND_LENGTH -------> :SERVER                 */
	/*              JAVA CLIENT: -------------- COMMAND ------------> :SERVER                 */
	/*              JAVA CLIENT: <-------------- RESULTS ------------ :SERVER                 */
	/*              JAVA CLIENT: <---------- CLOSE CONNECTION ------- :SERVER                 */
	/*                                                                                        */
	/******************************************************************************************/

		
		//SocketChannel socketNIO = new SocketChannelImpl();
		
		socket = new Socket(InetAddress.getByName(host), port);
		try {
			//By default in UNIX systems the keepalive message is sent after 20hours 
			//with Java we can not use the TCP_KEEPCNT, TCP_KEEPIDLE and TCP_KEEPINTVL options by session.
			//It is up to the server administrator and client user to configure them.
			//I guess it is because Solaris does not implement those options...
			//see: Net.c openjdk 6 and net_util_md.c openjdk 7
			//So in Java applications the only way to find out if the connection is broken (one router down)
			//is sending ping messages or something similar from the application layer. Java is a toy language...
			//Anyway I think the keepalive messages just work during the handshake phase, just after sending some
			//data over the link the keepalive does not work.
			// See: http://stackoverflow.com/questions/4345415/socket-detect-connection-is-lost
			socket.setKeepAlive(true);
			
			//It must be used the remote locale character set encoding
			//Besides you must know if the remote machine is using LITTLE or BIG ENDIAN. Why?
			//Because if the remote machine is using UTF-16/UTF-32 or any other multi-byte system, it depends on the ENDIANNESS.
			//UTF-8 just uses bytes so it does not depend on the ENDIANNESS.
			//TODO: my own protocol:
			//Java client: encode to TCPForkDaemon encode ----> Server C: encode from TCPForkDaemon to required character set (using iconv)
			//The TCPForkDaemon encode could be UTF-8, the Java client always encodes to UTF-8, then it sends to the server C application
			//where it always knows the command received is using UTF-8. Besides the server C application knows its local set encoding and
			//the ENDIANNESS, so it converts using iconv and byte swapping (endian.h) to the right character set encoding.
			//In this way we do not need to know about the remote encoding and everything could run automatically.
			byte [] commandEncoded = command.getBytes("UTF-8"); 
			
			DataOutputStream sendData = new DataOutputStream(socket.getOutputStream());
						
			// 1. COMMAND_LENGTH
			// This method sends the data like bytes using 4 system calls!!! Welcome to Java World...
			sendData.writeInt(commandEncoded.length);
				
			// 2. COMMAND
			sendData.write(commandEncoded);
			
			//DataInputStream receiveData = new DataInputStream(socket.getInputStream());
			//receiveData.read
			
			// 3. RESULTS
			// TODO: When the network infrastructure (between client and server) fails in this point 
			// (broken router for example) Could we stay here until TCP keepalive is sent?
			// (20 hours by default in Linux)
			// Impossible to use a timeout, because we do not know how much time is going to long the command :/
			// the only way to fix this issue in Java is sending ping messages (Could we fix it using custom settings in the OS
			// of the client and server machines? for example in Linux see /proc/sys/net/ipv4/)
			InputSource inputSource = new InputSource(socket.getInputStream());
			//It must be used the remote locale character set encoding. If using for example multi-byte system (like UTF-16) 
			//you must know about the ENDIANNESS for the remote machine.
			//TODO: my own protocol:
			//C server knows about its ENDIANNESS and character set so it can encode to TCPForkDaemon encode (which could be UTF-8) -> 
			//sends response to Java client and here we know the character set encoding is the defined for TCPForkDaemon protocol 
			//(for example UTF-8) In this way we do not need to know about the remote encoding and everything could run automatically. 
			inputSource.setEncoding("UTF-8");
			parser.setStream(socket.getInputStream());
			
			// 4. SERVER CLOSED CONNECTION
		}
		finally {
			if (out != null) {
				out.close();
			}
			socket.close();
		}
		
		//If everything went alright we should be able to retrieve the return 
		//status of the remotely executed command.
		return parser.getReturnValue();
	}

	
	/**
	 * Retrieve the standard output. <br>
	 * When there is nothing from the standard output this method returns null.
	 * 
	 * @see {@link TCPForkDaemon#getStderr()}
	 * @return the stdout stream
	 */
	public String getStdout() {
		return parser.getStdout();
	}
	
	
	/**
	 * Retrieve the stderr stream as a {@link String} from the command which 
	 * was run by the remote daemon 
	 * 
	 * @see {@link TCPForkDaemon#getStdout()}
	 * @return the stderr stream
	 */
	public String getStderr() {
		return parser.getStderr();
	}
}
