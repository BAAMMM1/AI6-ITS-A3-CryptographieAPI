package test;

import keyRSACreation.RSAKeyCreation;
import receiveSecureFile.RSF;
import sendSecureFile.SSF;

public class Test {

	public Test() {
		// TODO Auto-generated constructor stub
	}
	
	public void startTest(){
		
		RSAKeyCreation.main(new String[]{"KMueller"});
		
		RSAKeyCreation.main(new String[]{"FMeier"});
		
		SSF.main(new String[]{"KMueller.prv", "FMeier.pub","Brief.pdf","Brief"});
		//SSF.main(new String[]{"KMueller.prv", "FMeier.pub","Brief.pdf","Brief.ssf"});
		
		RSF.main(new String[]{"FMeier.prv", "KMueller.pub", "Brief.ssf", "BriefOut.pdf"});
		
	}

	public static void main(String[] args) {
		Test test = new Test();
		test.startTest();

	}
	
	

}
