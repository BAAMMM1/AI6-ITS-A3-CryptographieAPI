package utility;

public class ByteUtility {

	public ByteUtility() {
		// TODO Auto-generated constructor stub
	}
	
	
	/**
	 * Diese Methode verkettet zwei byte[] miteinander
	 */
	public static byte[] concatenate(byte[] ba1, byte[] ba2) {
		int len1 = ba1.length;
		int len2 = ba2.length;
		byte[] result = new byte[len1 + len2];
	
		// Fill with first array
		System.arraycopy(ba1, 0, result, 0, len1);
		// Fill with second array
		System.arraycopy(ba2, 0, result, len1, len2);
	
		return result;
	}

}
