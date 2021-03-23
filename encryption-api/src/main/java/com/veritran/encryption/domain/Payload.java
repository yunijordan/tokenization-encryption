package com.veritran.encryption.domain;

public class Payload {

    private Object payload;

    public Payload() {

    }

    public Payload(Object payload) {
        this.payload = payload;
    }


    public Object getPayload() {
        return payload;
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }
}
