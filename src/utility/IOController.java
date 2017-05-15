package utility;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class IOController {

	private static final int BLOCK_SIZE = 8;

	public IOController() {
	}

	public LinkedList<byte[]> readFileInBlockList(String path) {
		LinkedList<byte[]> toReturn = new LinkedList<byte[]>();

		InputStream inStream;

		try {
			inStream = new FileInputStream(path);

			while (inStream.available() != 0) {
				byte[] buffer;

				buffer = new byte[BLOCK_SIZE];

				inStream.read(buffer);
				toReturn.add(buffer);
			}
			inStream.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
		return toReturn;
	}

	public void writeFileBlockList(List<byte[]> byteArrayList, String path) {
		OutputStream outStream;
		try {
			outStream = new FileOutputStream(path);

			byte[] toWriteBytes = new byte[byteArrayList.size() * BLOCK_SIZE];

			int byteIndex = 0;

			for (byte[] byteArray : byteArrayList) {

				for (int index = 0; index < byteArray.length; index++) {
					toWriteBytes[byteIndex++] = byteArray[index];
				}
			}

			outStream.write(toWriteBytes);
			outStream.close();

		} catch (IOException e1) {
			e1.printStackTrace();
		}

	}

}
