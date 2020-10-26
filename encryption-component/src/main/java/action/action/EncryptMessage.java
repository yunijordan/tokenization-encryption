package action.action;

import infrastructure.EncryptUtils;

public class EncryptMessage {

    public String execute(String aValue, String publicKeyStr) {
        return EncryptUtils.encrypt(aValue, publicKeyStr);
    }

}
