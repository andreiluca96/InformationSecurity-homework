package com.company;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

import static com.company.CryptoUtils.encryptBlock;

public class ActorKM {
    private static final String k1 = "aaaaaaaaaaaaaaaa";
    private static final String k2 = "bbbbbbbbbbbbbbbb";
    private static final String k3 = "cccccccccccccccc";

    public static void main(String[] args) throws IOException, InterruptedException {
        ServerSocket actorKMSocket = new ServerSocket(6791);

        System.out.println("ActorA:");
        recieveModeAndSendKey(actorKMSocket);

        System.out.println("ActorB:");
        recieveModeAndSendKey(actorKMSocket);
    }

    private static void recieveModeAndSendKey(ServerSocket actorKMSocket) throws IOException {
        String cypherMode;
        Socket actorSocker = actorKMSocket.accept();

        BufferedReader inActor = new BufferedReader(new InputStreamReader(actorSocker.getInputStream()));
        DataOutputStream outActor = new DataOutputStream(actorSocker.getOutputStream());

        cypherMode = inActor.readLine();
        System.out.println(String.format("Received the cypherMode <%s>.", cypherMode));

        System.out.println(String.format("Sending the <%s> key to actor", cypherMode));
        if (cypherMode.compareToIgnoreCase("ECB") == 0) {
            outActor.writeBytes(encryptBlock(k1, k3) + "\n");
        } else {
            if (cypherMode.compareToIgnoreCase("CBC") == 0) {
                outActor.writeBytes(encryptBlock(k2, k3) + "\n");
            } else {
                throw new IllegalStateException("Wrong cypher mode!!!");
            }
        }
    }
}
