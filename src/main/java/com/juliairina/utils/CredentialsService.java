package com.juliairina.utils;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileReader;
import java.io.IOException;

public class CredentialsService {

    private String fileDestination;
    private JSONParser jsonParser;
    JSONArray clients;

    public CredentialsService(String fileDestination) throws IOException, ParseException {
        this.fileDestination = fileDestination;
        jsonParser = new JSONParser();

        FileReader reader = new FileReader(fileDestination);
        Object object = jsonParser.parse(reader);
        clients = (JSONArray) object;
    }

    public boolean checkCredentials(String name, String password) {
        boolean isPresent = false;
        for (Object client : clients) {
            JSONObject jsonClient = (JSONObject) client;
            if (jsonClient.get("name").equals(name) && jsonClient.get("password").equals(password)) {
                isPresent = true;
                break;
            }
        }
        return isPresent;
    }

}
