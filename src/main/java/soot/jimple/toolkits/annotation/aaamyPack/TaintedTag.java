package soot.jimple.toolkits.annotation.aaamyPack;

import soot.tagkit.AttributeValueException;
import soot.tagkit.Tag;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;

public class TaintedTag implements Tag {

    private int[] taintedParamIndex;

    public TaintedTag(int taintedParamIndex) {
        this.taintedParamIndex = new int[20];
        this.taintedParamIndex[0] = taintedParamIndex;
    }

    public TaintedTag(int[] taintedParamIndex) {
        this.taintedParamIndex = new int[20];
        this.taintedParamIndex= taintedParamIndex;
    }

    public String getName() {
        return "pf.bm.TaintedTag";
    }

    public int[] getTaintedParamIndex() {
        return taintedParamIndex;
    }

    public void setTaintedParamIndex(int[] taintedParamIndex) {
        this.taintedParamIndex = taintedParamIndex;
    }

    public byte[] getValue() throws AttributeValueException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(4);
        DataOutputStream doa = new DataOutputStream(baos);

        try {
            for (int i = 0; i < taintedParamIndex.length; i++) {
                doa.write(taintedParamIndex[i]);
            }
            doa.flush();
        } catch (IOException e) {
            System.err.println(e);
            throw new RuntimeException(e);
        }

        return baos.toByteArray();
    }
}
