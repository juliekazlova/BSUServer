package com.juliairina.server;

import com.juliairina.scrambler.RSAScrambler;
import com.juliairina.scrambler.SerpentScrambler;
import com.juliairina.utils.Command;
import com.juliairina.utils.CredentialsService;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class ServerThread extends Thread {

    private final static int FILE_SIZE = 8192;//6022386;
    private final static String endMessage = "exit";
    private final static String requestMessage = "request";
    private final static String saveMessage = "save";
    private final static String acceptMessage = "accept";
    private final static String denyMessage = "deny";
    private final static String generateMessage = "generate";
    private final static String DELETE_MESSAGE = "delete";
    private final static String LOG_IN_MESSAGE = "login";

    private final static String CREDENTIALS_DESTINATION = "/Users/yuliakazlova/Downloads/remoteNotepad-add-ui/Server/resourses/credentials.properties";
    private final static String STORAGE_FOLDER_DESTINATION = "/Users/yuliakazlova/Downloads/remoteNotepad-add-ui/Server/storage/";


    private Socket clientSocket;
    private String clientAddress;
    private InputStream inputStream;
    private OutputStream outputStream;

    private RSAScrambler rsaScrambler;
    private SerpentScrambler serpentScrambler;
    private CredentialsService credentialsService;

    private Map<String, Command> messagesMap;

    private static Logger log = Logger.getLogger(Server.class.getName());

    public ServerThread(Socket clientSocket) throws IOException, ParseException {
        this.clientSocket = clientSocket;
        clientAddress = clientSocket.getInetAddress().getHostAddress();
        inputStream = clientSocket.getInputStream();
        outputStream = clientSocket.getOutputStream();

        rsaScrambler = null;
        serpentScrambler = null;
        credentialsService = new CredentialsService(CREDENTIALS_DESTINATION);

        messagesMap = new HashMap<>();

        messagesMap.put(endMessage, string -> {
            try {
                receiveEndMessage();
            } catch (Exception exception) {
                log.warning(exception.getMessage());
            }
        });
        messagesMap.put(requestMessage, string -> {
            try {
                receiveRequestMessage(string);
            } catch (Exception exception) {
                log.warning(exception.getMessage());
            }
        });
        messagesMap.put(saveMessage, string -> {
            try {
                receiveSaveMessage(string);
            } catch (Exception exception) {
                log.warning(exception.getMessage());
            }
        });
        messagesMap.put(generateMessage, message -> {
            try {
                receiveGenerateMessage();
            } catch (Exception exception) {
                log.warning(exception.getMessage());
            }
        });
        messagesMap.put(DELETE_MESSAGE, string -> {
            try {
                receiveDeleteMessage(string);
            } catch (Exception exception) {
                log.warning(exception.getMessage());
            }
        });
        messagesMap.put(LOG_IN_MESSAGE, string -> {
            try {
                receiveLogInMessage(string);
            } catch (Exception exception) {
                log.warning(exception.getMessage());
            }
        });

        start();
    }

    @Override
    public void run() {
        log.info(clientAddress + ": CONNECTION ESTABLISHED");
        try {
            byte[] bytes;
            String command;
            String[] commandSplit;

            receivePublicKey();

            sendSessionKey();

            while (true) {
                bytes = readBytes();
                command = new String(bytes);
                commandSplit = command.split(" ");

                if (commandSplit.length > 1) {
                    messagesMap.get(commandSplit[0]).execute(commandSplit[1]);
                } else {
                    messagesMap.get(commandSplit[0]).execute(null);
                }

            }
        } catch (
                Exception exception) {
            log.warning(clientAddress + ": CONNECTION IS CLOSED");
        }

    }

    public void receiveLogInMessage(String credentials)
            throws IOException, GeneralSecurityException {
        log.info(clientAddress + ": GOT REQUEST FOR LOG IN ");
        String[] credentials_split = credentials.split("-");
        String name = credentials_split[0];
        String password = credentials_split[1];
        if (credentialsService.checkCredentials(name, password)) {
            log.info(clientAddress + ": SENDING ACCEPT MESSAGE... ");
            writeBytes(acceptMessage.getBytes());
            log.info(clientAddress + ": USER IS LOGGED IN ");
        } else {
            log.info(clientAddress + ": SENDING DENY MESSAGE... ");
            writeBytes(denyMessage.getBytes());
            log.info(clientAddress + ": INVALID CREDENTIALS ");
        }
    }

    public void receiveDeleteMessage(String fileName)
            throws IOException, GeneralSecurityException {
        log.info(clientAddress + ": GOT REQUEST FOR DELETING FILE " + fileName);
        if (deleteFile(fileName)) {
            log.info(clientAddress + ": SENDING ACCEPT MESSAGE... " + fileName);
            writeBytes(acceptMessage.getBytes());
            log.info(clientAddress + ": FILE IS SUCCESSFULLY DELETED " + fileName);
        } else {
            log.info(clientAddress + ": SENDING DENY MESSAGE... " + fileName);
            writeBytes(denyMessage.getBytes());
            log.info(clientAddress + ": FILE IS NOT FOUND " + fileName);
        }
    }

    public void receiveEndMessage() {
        log.info(clientAddress + ": CONNECTION ABORTED");
        stopClient();
    }

    public void receiveRequestMessage(String fileName)
            throws IOException, GeneralSecurityException {
        byte[] bytes;
        log.info(clientAddress + ": GOT REQUEST FOR FILE " + fileName);
        try {
            bytes = readBytesFromFile(fileName);
            log.info(clientAddress + ": SENDING ACCEPT MESSAGE... " + fileName);
            writeBytes(acceptMessage.getBytes());
            log.info(clientAddress + ": SENDING FILE... " + fileName);
            writeBytes(bytes);
            log.info(clientAddress + ": FILE SENT " + fileName);
        } catch (IOException exception) {
            log.info(clientAddress + ": SENDING DENY MESSAGE... " + fileName);
            writeBytes(denyMessage.getBytes());
            log.info(clientAddress + ": FILE IS NOT FOUND " + fileName);
        }
    }

    public void receiveSaveMessage(String fileName) throws IOException, GeneralSecurityException {
        byte[] bytes;
        log.info(clientAddress + ": GOT REQUEST FOR FILE SAVING " + fileName);
        try {
            log.info(clientAddress + ": SENDING ACCEPT MESSAGE... " + fileName);
            writeBytes(acceptMessage.getBytes());
            bytes = readBytes();
            writeBytesToFile(bytes, fileName);
        } catch (IOException exception) {
            log.info(clientAddress + ": SENDING DENY MESSAGE... " + fileName);
        }
    }

    public void receiveGenerateMessage() throws IOException, GeneralSecurityException {
        log.info(clientAddress + ": GET GENERATE MESSAGE");
        serpentScrambler = null;
        sendSessionKey();
    }

    public void stopClient() {
        try {
            clientSocket.close();
        } catch (IOException exception) {
            log.info(exception.getMessage());
        }
    }

    private void sendSessionKey() throws IOException, GeneralSecurityException {
        log.info("SEND SESSION KEY");
        serpentScrambler = new SerpentScrambler();
        writeBytes(rsaScrambler.encrypt(serpentScrambler.getKey().getEncoded()), false);
        writeBytes(rsaScrambler.encrypt(serpentScrambler.getIv()), false);
        log.info("SESSION KEY IS SENT");
    }

    private void receivePublicKey() throws IOException, GeneralSecurityException {
        byte[] bytes = null;
        log.info("GET PUBLIC KEY");
        bytes = readBytes();
        rsaScrambler = new RSAScrambler(bytes);
    }

    private byte[] readBytes() throws IOException, GeneralSecurityException {
        int count;
        byte[] bytes = new byte[FILE_SIZE];
        while ((count = inputStream.read(bytes)) > 0) {
            bytes = Arrays.copyOfRange(bytes, 0, count);
            break;
        }
        if (!isConnectionSecured()) {
            log.warning("CONNECTION IS NOT SECURED");
        } else {
            bytes = serpentScrambler.decrypt(bytes);
        }
        return bytes;
    }

    private byte[] readBytesFromFile(String filename) throws IOException {
        File file = new File(STORAGE_FOLDER_DESTINATION + filename);
        return Files.readAllBytes(file.toPath());
    }

    private boolean deleteFile(String filename) {
        File file = new File(STORAGE_FOLDER_DESTINATION + filename);
        return file.delete();
    }

    private void writeBytes(byte[] bytes)
            throws IOException, GeneralSecurityException {
        if (!isConnectionSecured()) {
            log.warning("CONNECTION IS NOT SECURED");
        } else {
            bytes = serpentScrambler.encrypt(bytes);
        }
        outputStream.write(bytes);
        outputStream.flush();
    }

    private void writeBytes(byte[] bytes, boolean isSecured)
            throws IOException, GeneralSecurityException {
        if (!isConnectionSecured() || !isSecured) {
            log.warning("CONNECTION IS NOT SECURED");
        } else {
            bytes = serpentScrambler.encrypt(bytes);
        }
        outputStream.write(bytes);
        outputStream.flush();
    }

    private void writeBytesToFile(byte[] bytes, String fileName) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(
                STORAGE_FOLDER_DESTINATION + fileName);
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
        bufferedOutputStream.write(bytes, 0, bytes.length);
        bufferedOutputStream.flush();
    }

    private boolean isConnectionSecured() {
        if (serpentScrambler != null) {
            return true;
        } else {
            return false;
        }
    }
}