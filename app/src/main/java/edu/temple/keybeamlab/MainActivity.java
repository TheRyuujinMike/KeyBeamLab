package edu.temple.keybeamlab;

import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.os.Parcelable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import static android.nfc.NdefRecord.createMime;

public class MainActivity extends AppCompatActivity implements NfcAdapter.CreateNdefMessageCallback{

    EditText sendEditText, receivedEditText, receivedEncryptedText;
    String sendingString, receivedString, myPublicKey, myPrivateKey, pairedPublicKey;
    String[] currentKeyPair;
    NfcAdapter mNfcAdapter;

    @Override
    protected void onPause() {
        super.onPause();
    }

    @Override
    public void onResume() {
        super.onResume();
        // Check to see that the Activity started due to an Android Beam
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processIntent(getIntent());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        sendEditText = (EditText) findViewById(R.id.textToSend);
        receivedEditText = (EditText) findViewById(R.id.textReceived);
        receivedEncryptedText = (EditText) findViewById(R.id.textEncryptedReceived);

        sendingString = "";
        receivedString = "";

        currentKeyPair = generateNewPair();
        myPrivateKey = currentKeyPair[0];
        myPublicKey = currentKeyPair[1];
        pairedPublicKey = "empty";

        // Check for available NFC Adapter
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (mNfcAdapter == null) {
            Toast.makeText(this, "NFC is not available", Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        // Register callback
        mNfcAdapter.setNdefPushMessageCallback(this, this);

        /**Testing Key Creation

        Log.d("Private Key", myPrivateKey);
        Log.d("Public Key", myPublicKey);

         **/

        /**Testing Encryption and Decryption

         String myTestString = encryptText("Eureka!", myPublicKey);
         String myTestResult = decryptText(myTestString, myPrivateKey);
         Log.d("Encrypt/Decrypt Test", myTestResult);

         **/

    }

    private String encryptText(String textToEncrypt, String publicKeyString) {

        String encryptedText = "";
        PublicKey publicKey = null;

        //Change publicKeyString to PublicKey type

        try {
            byte[] publicBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(spec);
        }
        catch(Exception e) {
            Log.e("RSA", "RSA Public key error");
        }

        //Encrypt

        try {
            Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, input);
            cipherOutputStream.write(textToEncrypt.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte[] vals = outputStream.toByteArray();
            encryptedText = new String(Base64.encodeToString(vals, Base64.DEFAULT));

        }
        catch (Exception e) {
            Log.e("RSA", "Encryption Error");
        }

        return encryptedText;

    }

    private String decryptText(String textToDecrypt, String privateKeyString) {

        String decryptedText = "";
        PrivateKey privateKey = null;

        //Change privateKeyString to PrivateKey type

        try {
            byte [] privateBytes = Base64.decode(privateKeyString, Base64.DEFAULT);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        }
        catch(Exception e) {
            Log.e("RSA", "RSA Private key error");
        }

        //Decrypt

        try {
            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(textToDecrypt, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            decryptedText = new String(bytes, 0, bytes.length, "UTF-8");
        }
        catch (Exception e) {
            Log.e("RSA", "Decryption Errpr");
        }

        return decryptedText;

    }

    private String[] generateNewPair() {

        /**Returns a 2 element string array where the first element is a new Private key, and
         the second element is a new Public key**/

        KeyPairGenerator keyPairGenerator = null;
        KeyPair keyPair;
        String[] newPair = {null, null};

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        keyPair = keyPairGenerator.generateKeyPair();

        //Change Private Key to String
        byte[] privateKeyBytes = Base64.encode(keyPair.getPrivate().getEncoded(),Base64.DEFAULT);
        String privateKey = new String(privateKeyBytes);

        //Change Public Key to String
        byte[] publicKeyBytes = Base64.encode(keyPair.getPublic().getEncoded(), Base64.DEFAULT);
        String publicKey = new String(publicKeyBytes);

        newPair[0] = privateKey;
        newPair[1] = publicKey;

        return newPair;

    }

    @Override
    public NdefMessage createNdefMessage(NfcEvent nfcEvent) {

        if (!pairedPublicKey.equals("empty")) {

            sendingString = encryptText(sendEditText.getText().toString(), pairedPublicKey);

        }

        String text = myPublicKey + "#SPLITHERE#" + pairedPublicKey + "#SPLITHERE#" + sendingString;
        NdefMessage msg = new NdefMessage(
                new NdefRecord[] { createMime(
                        "application/vnd.com.keybeamlab.android.beam", text.getBytes())
                });
        return msg;

    }

    @Override
    public void onNewIntent(Intent intent) {
        // onResume gets called after this to handle the intent
        setIntent(intent);
    }

    /**
     * Parses the NDEF Message from the intent and prints to the EditText
     */
    void processIntent(Intent intent) {
        Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
                NfcAdapter.EXTRA_NDEF_MESSAGES);
        // only one message sent during the beam
        NdefMessage msg = (NdefMessage) rawMsgs[0];
        // record 0 contains the MIME type, record 1 is the AAR, if present
        receivedString = new String(msg.getRecords()[0].getPayload());

        String[] parts = receivedString.split("#SPLITHERE#");

        if (pairedPublicKey.equals(parts[0])) {

            receivedString = decryptText(parts[2], myPrivateKey);

            receivedEncryptedText.setText(parts[2]);
            receivedEditText.setText(receivedString);

        }
        else {

            pairedPublicKey = parts[0];

            Toast.makeText(this, "You now have the other user's public key.", Toast.LENGTH_SHORT).show();

        }

    }

}
