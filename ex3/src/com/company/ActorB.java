package com.company;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import static com.company.CryptoUtils.decryptBlock;
import static com.company.CryptoUtils.decryptMessage;

public class ActorB {
    private static final String k3 = "cccccccccccccccc";

    public static void main(String[] args) throws IOException, InterruptedException {
        ServerSocket actorBSocket = new ServerSocket(6789);

        Socket actorACommunicationSocket = actorBSocket.accept();
        BufferedReader inFromActorA =
                new BufferedReader(new InputStreamReader(actorACommunicationSocket.getInputStream()));
        DataOutputStream outToActorA = new DataOutputStream(actorACommunicationSocket.getOutputStream());

        String cypherMode = inFromActorA.readLine();
        System.out.println(String.format("Received from actorA the cypherMode <%s>.", cypherMode));

        System.out.println("Sleeping for 1 sec...");
        Thread.sleep(1000);

        System.out.println("Starting connection to keyManager...");
        Socket keyManagerSocket = new Socket("localhost", 6791);
        System.out.println("The connection to keyManager started successfully.");

        BufferedReader inFromKeyManager = new BufferedReader(new InputStreamReader(keyManagerSocket.getInputStream()));
        DataOutputStream outToKeyManager = new DataOutputStream(keyManagerSocket.getOutputStream());

        System.out.println(String.format("Sent the following cypherMode <%s> to keyManager.", cypherMode));
        outToKeyManager.writeBytes(cypherMode + "\n");

        String encryptedKey = inFromKeyManager.readLine();
        System.out.println(String.format("Received from keyManager the following encryptedKey <%s>.", encryptedKey));

        String decryptedKey = decryptBlock(encryptedKey, k3);
        System.out.println(String.format("Decrypted the key and obtained the key <%s>.", decryptedKey));

        outToActorA.writeBytes("READY" + "\n");

        System.out.println("Sleeping for 1 sec...");
        Thread.sleep(1000);

        System.out.println("Receiving the encrypted message.");
        List<String> encryptedBlocks = new ArrayList<>();
        Integer blockSize = Integer.valueOf(inFromActorA.readLine());
        for (int i = 0; i < blockSize; i++) {
            encryptedBlocks.add(inFromActorA.readLine());
        }

        System.out.println(String.format("Decrypting the encrypted blocks <%s>...", encryptedBlocks));

        String decryptedMessage = decryptMessage(encryptedBlocks, decryptedKey, cypherMode);

        System.out.println(String.format("The decrypted text is: <%s>", decryptedMessage));
    }


}
