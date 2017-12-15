package com.company;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.List;

import static com.company.CryptoUtils.decryptBlock;
import static com.company.CryptoUtils.encryptMessage;

public class ActorA {
    private static final String plainText = "Ana are mere dulci...";
    private static final String k3 = "cccccccccccccccc";

    public static void main(String[] args) throws IOException {
        Socket actorBSocket = new Socket("localhost", 6789);
        Socket keyManagerSocket = new Socket("localhost", 6791);

        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        BufferedReader inFromActorB = new BufferedReader(new InputStreamReader(actorBSocket.getInputStream()));
        BufferedReader inFromKeyManager = new BufferedReader(new InputStreamReader(keyManagerSocket.getInputStream()));

        DataOutputStream outToActorB = new DataOutputStream(actorBSocket.getOutputStream());
        DataOutputStream outToKeyManager = new DataOutputStream(keyManagerSocket.getOutputStream());

        System.out.println("Insert your cypher mode(CBC or ECB):");
        String cypherMode = inFromUser.readLine();

        if (!(cypherMode.compareToIgnoreCase("CBC") == 0 || cypherMode.compareToIgnoreCase("ECB") == 0)) {
            throw new IllegalStateException("The cypher mode must be CBC or EBC.");
        }

        System.out.println(String.format("The user added the following cypherMode <%s>.", cypherMode));

        outToActorB.writeBytes(cypherMode + '\n');
        System.out.println(String.format("Sent the following cypherMode <%s> to actorB.", cypherMode));

        outToKeyManager.writeBytes(cypherMode + '\n');
        System.out.println(String.format("Sent the following cypherMode <%s> to keyManager.", cypherMode));


        String encryptedKey = inFromKeyManager.readLine();
        System.out.println(String.format("Received from keyManager the following encryptedKey <%s>.", encryptedKey));

        String actorBState = inFromActorB.readLine();
        System.out.println(String.format("Received from actorB the following message <%s>.", actorBState));

        if (actorBState.compareToIgnoreCase("READY") != 0) {
            throw new IllegalStateException("The actorB is not ready.");
        }

        String decryptedKey = decryptBlock(encryptedKey, k3);
        System.out.println(String.format("Decrypted the key and obtained the key <%s>.", decryptedKey));

        List<String> encryptedBlocks = encryptMessage(decryptedKey, plainText, cypherMode);
        System.out.println(String.format("Sending the encrypted blocks <%s>.", encryptedBlocks));
        outToActorB.writeBytes(String.valueOf(encryptedBlocks.size()) + "\n");

        encryptedBlocks
                .forEach(block -> {
                    try {
                        outToActorB.writeBytes(block + "\n");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });


    }
}
