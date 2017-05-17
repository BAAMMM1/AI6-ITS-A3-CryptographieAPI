package utility;

public class Printer {
	
	private static final boolean testMode = false;

	public static void promptTestOut(Object obj, String string){
		if(testMode){
			System.out.println(obj.toString() + ": " + string);
		}		
	}
	
	public static void promptErrTestOut(Object obj, String string){
		if(testMode){
			System.err.println(obj.toString() + ": " + string);
		}		
	}	
	
	public static void prompt(Object obj, String string){
		System.out.println(obj.toString() + ": " + string);
	}
	
	public static void errPrompt(Object obj, String string){
		System.err.println(obj.toString() + ": " + string);
	}
	
	/**
	 * Diese Methode gibt eine Fehlermeldung sowie eine Beschreibung der
	 * Ausnahme aus. Danach wird das Programm beendet.
	 *
	 * @param msg
	 *            eine Beschreibung fuer den Fehler
	 * @param ex
	 *            die Ausnahme, die den Fehler ausgeloest hat
	 */
	public static void error(String msg, Exception e) {
		System.out.println(msg);
		System.out.println(e.getMessage());
		System.exit(0);
	}
}
