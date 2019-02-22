package com.additionsecurity;

public interface IMobileAwarenessCallback {
    void onMessage(int messageType, int messageSubType, byte[] data1, byte[] data2);
}
