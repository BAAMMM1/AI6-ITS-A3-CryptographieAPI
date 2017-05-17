package test;

import model.keyRSACreation.RSAKeyCreation;
import model.receiveSecureFile.RSF;
import model.sendSecureFile.SSF;

public class Test {

	public Test() {
	}
	
	public void startTest(){
		
		RSAKeyCreation.main(new String[]{"KMueller"});
		
		RSAKeyCreation.main(new String[]{"FMeier"});
		
		SSF.main(new String[]{"KMueller.prv", "FMeier.pub","Brief.pdf","Brief"});
		
		RSF.main(new String[]{"FMeier.prv", "KMueller.pub", "Brief.ssf", "BriefOut.pdf"});
		
	}
	
public void startTest2(){
		
		RSAKeyCreation.main(new String[]{"Christian"});
		
		SSF.main(new String[]{"Christian.prv", "Test.pub","Brief.pdf","test2"});
		
	}

	public static void main(String[] args) {
		Test test = new Test();
		test.startTest2();

	}
	
	

}
