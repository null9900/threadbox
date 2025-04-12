package threadbox;

import java.io.FileWriter;
import java.io.IOException;

public class Threadbox {

	public static void sandbox_ps() {
	    try {
	        FileWriter myWriter = new FileWriter("/sys/kernel/security/funcsandbox/sandbox_ps");
	        myWriter.write(" ");
	        myWriter.close();
	      } catch (IOException e) {
	        e.printStackTrace();
	      }
	}
	
	public static void permissions(String promises, String debug, Boolean complain) {
		try {
	        FileWriter p = new FileWriter("/sys/kernel/security/funcsandbox/promises");
	        FileWriter d = new FileWriter("/sys/kernel/security/funcsandbox/debug");
	        FileWriter c = new FileWriter("/sys/kernel/security/funcsandbox/learning_mode");
	        p.write(promises);
			if(debug.length()!=0) {
		        d.write(debug);
			}
			if(complain==true) {
		        c.write(" ");
			}
			p.close();
			d.close();
			c.close();
		} catch (IOException e) {
	        e.printStackTrace();
		}
	}
	
}

