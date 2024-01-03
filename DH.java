import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class DH {

    public static void main(String[] args)  throws Exception 
        {
        if (args.length < 1) {
            System.out.println("Usage: java DH private_key [public_key]");
            System.exit(1);
        }
    }
     String privateKey = args[0];

        if (args.length == 1) {
            
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGenerator.initialize(2048); 

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println("Public Key: " + bytesToHex(publicKey.getEncoded()));
        } 
        else {
            // Step 2: Generate shared secret using private and public keys
            String recipientPublicKey = args[1];

            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(hexStringToByteArray(recipientPublicKey));
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGenerator.initialize(2048);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKeyObject = keyPair.getPrivate();

            DHParameterSpec dhParameterSpec = ((DHPublicKey) publicKey).getParams();

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(privateKeyObject);
            keyAgreement.doPhase(publicKey, true);

            byte[] secret = keyAgreement.generateSecret();
            System.out.println("Shared Secret (Session Key): " + bytesToHex(secret));
        }
    }
}

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}

   
    

