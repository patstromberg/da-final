import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;

import org.json.JSONObject;

public class LogReader {

	static String fileName;
	static String transmit;
	static String description;
	static String logName;
	static String customerId;
	static String sharedKey;
	static String verbose = "N";
	
    private static void printUsage() {
        System.out.println("Usage: LogReader");
        System.out.println("               -fileName <file to monitor for searchrate results>");
        System.out.println("               -transmit <Y or N to indicate whether to attempt to transmit data to Log Analytics>");
        System.out.println("               -description <label to identify this machine / run in Log Analytics");
        System.out.println("               -logName <the name of the custom log in Log Analytics");
        System.out.println("               -customerId <Log Analytics customer ID - obtained on the Azure portal>");
        System.out.println("               -sharedKey <key required for transmission - also acquired from Log Analytics in Azure portal>");
        System.out.println("               -verbose [if Y then print debug output]");
    }

    private static boolean validateArgs(String args[]) {
        boolean valid = true;
        for (int i = 0; i < args.length - 1;) {
            if (args[i].equals("-transmit")) {
                transmit = args[i + 1];
                i += 2;
            } else if (args[i].equals("-fileName")) {
                fileName = args[i + 1];
                i += 2;
            } else if (args[i].equals("-description")) {
                description = args[i + 1];
                i += 2;
            } else if (args[i].equals("-logName")) {
                logName = args[i + 1];
                i += 2;
            } else if (args[i].equals("-customerId")) {
                customerId = args[i + 1];
                i += 2;
            } else if (args[i].equals("-sharedKey")) {
                sharedKey = args[i + 1];
                i += 2;
            } else if (args[i].equals("-verbose")) {
                verbose = args[i + 1];
                i += 2;
            } else {
                i++;
            }
        }
        if (transmit == null 
        		|| transmit.length() == 0 
        		|| fileName == null 
        		|| fileName.length() == 0 
        		|| description == null 
        		|| description.length() == 0 
        		|| customerId == null 
        		|| customerId.length() == 0 
        		|| sharedKey == null 
        		|| sharedKey.length() == 0 
        		|| logName == null 
        		|| logName.length() == 0) {
            valid = false;
        }
        return valid;
    }

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		if (!validateArgs(args)) {
			printUsage();
		}
		else {
			try {
				startReading(fileName);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
//		fileName = args[0];
//		transmit = args[1];
//		description = args[2];
//		logName = args[3];
//		customerId = args[4];
//		sharedKey = args[5];
	}
	
    private static boolean canBreak = false;

    public static void startReading(String filename) throws InterruptedException, IOException {
        canBreak = false;
        String line;
        try {
            LineNumberReader lnr = new LineNumberReader(new FileReader(filename));
            while (!canBreak)
            {
                line = lnr.readLine();
                if (line == null) {
                    if (verbose.equals("Y")) System.out.println("waiting");
                    Thread.sleep(3000);
                    continue;
                }
                processLine(line);
            }
            lnr.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void stopReading() {
        canBreak = true;
    }

    private static void postMessage(String json) {

		String Signature = "";
		String encodedHash = "";
		String url = "";

		// Date object
		Date date = new Date();

		// Todays date input for OMS Log Analytics
		SimpleDateFormat sdf = new SimpleDateFormat("E, dd MMM YYYY HH:mm:ss zzz");
		sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
		String timeNow = sdf.format(date);   

		// String for signing the key
		String stringToSign="POST\n" + json.length() + "\napplication/json\nx-ms-date:"+timeNow+"\n/api/logs";

		try {
			byte[] decodedBytes = Base64.getDecoder().decode(sharedKey);

			Mac hasher = Mac.getInstance("HmacSHA256");
			hasher.init(new SecretKeySpec(decodedBytes, "HmacSHA256"));
			byte[] hash = hasher.doFinal(stringToSign.getBytes());
		    
			encodedHash = DatatypeConverter.printBase64Binary(hash);
			Signature = "SharedKey " + customerId + ":" + encodedHash;
	    
			url = "https://" + customerId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";	    
			URL objUrl = new URL(url);
			HttpsURLConnection con = (HttpsURLConnection) objUrl.openConnection();
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("Log-Type",logName);
			con.setRequestProperty("x-ms-date", timeNow);
			con.setRequestProperty("Authorization", Signature);
	        
			DataOutputStream wr = new DataOutputStream(con.getOutputStream());
			wr.writeBytes(json);
			wr.flush();
			wr.close();

			int responseCode = con.getResponseCode();
			if (verbose.equals("Y")) {
				System.out.println("\nSending 'POST' request to URL : " + url);
				System.out.println("Post parameters : " + json);
				System.out.println("Response Code : " + responseCode);
			}
		}
		catch (Exception e) {
			System.out.println("Catch statement: " + e);
		}
    }

    private static void processLine(String s) {
        //processing line
    	try {
    		JSONObject jo = new JSONObject();
    		if (verbose.equals("Y")) System.out.println("line = " + s);
	    	StringTokenizer st = new StringTokenizer(s," ");
	    	int colNum = 1;
	    	while (st.hasMoreTokens()) {
	    		String value = st.nextToken();
	    		if (value.indexOf("|") < 0) {
	    			// this is not a column break - it is a number
	    			Double dVal = new Double(value);
	    			switch (colNum) {
	    			case 1:
		    			jo.put("throughput_recent", dVal);
	    			case 2:
	    				jo.put("throughput_average", dVal);
	    			case 3:
	    				jo.put("response_recent",dVal);
	    			case 4:
	    				jo.put("response_average", dVal);
	    			case 5:
	    				jo.put("reponse_999", dVal);
	    			}
	    			colNum++;
	    		}
	    	}
	    	jo.put("machine_name", description);
	    	if (transmit.equals("Y")) {
		    	if (verbose.equals("Y")) System.out.println("posting " + jo.toString());
		    	postMessage(jo.toString());
	    	}
	    	else {
	    		if (verbose.equals("Y")) System.out.println("DEBUG " + jo.toString());
	    	}
    	}
    	catch (Exception e)
    	{
    		e.printStackTrace();
    	}
    }
}
