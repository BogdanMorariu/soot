package soot.jimple.toolkits.annotation.aaamyPack;

import soot.tagkit.AttributeValueException;
import soot.tagkit.Tag;

import java.util.Arrays;

public class TaintedTag implements Tag {

    private int[] sensitiveParamsIndexes;

    private int[] compromisedParamIndexes;

    private boolean visited;

    public TaintedTag(int[] sensitiveParamsIndexes) {
        this.sensitiveParamsIndexes = sensitiveParamsIndexes;
        this.compromisedParamIndexes = new int[sensitiveParamsIndexes.length];
        this.visited = false;
    }

    public TaintedTag(int[] sensitiveParamsIndexes, int[] compromisedParamIndexes) {
        if(sensitiveParamsIndexes.length != compromisedParamIndexes.length)
            throw new IllegalArgumentException("Invalid sizes for sensitive and compromised indexes!");
        this.sensitiveParamsIndexes = sensitiveParamsIndexes;
        this.compromisedParamIndexes = compromisedParamIndexes;
        this.visited = false;
    }

    public String getName() {
        return "pf.bm.TaintedTag";
    }

    public int[] getSensitiveParamsIndexes() {
        return sensitiveParamsIndexes;
    }

    public void setSensitiveParamsIndexes(int[] sensitiveParamsIndexes) {
        this.sensitiveParamsIndexes = sensitiveParamsIndexes;
    }

    public int[] getCompromisedParamIndexes() {
        return compromisedParamIndexes;
    }

    public void setCompromisedParamIndexes(int[] compromisedParamIndexes) {
        this.compromisedParamIndexes = compromisedParamIndexes;
    }

    public void updateCompromisedParamIndexes(int[] compromisedParamIndexes) {
        if (this.compromisedParamIndexes.length != compromisedParamIndexes.length) {
            throw new RuntimeException("Failed to updated compromisedIndexes. lengths are: " + this.compromisedParamIndexes.length + " and " + compromisedParamIndexes.length);
        }
        for (int i = 0; i < this.compromisedParamIndexes.length; i++) {
            this.compromisedParamIndexes[i] = this.compromisedParamIndexes[i] | compromisedParamIndexes[i];
        }
    }

    public boolean isVisited() {
        return visited;
    }

    public void setVisited(boolean visited) {
        this.visited = visited;
    }

    public byte[] getValue() throws AttributeValueException {
        return "".getBytes();
    }

    @Override
    public String toString() {
        return "TaintedTag{" +
                "sensitiveParamsIndexes=" + Arrays.toString(sensitiveParamsIndexes) +
                ", compromisedParamIndexes=" + Arrays.toString(compromisedParamIndexes) +
                ", visited=" + visited +
                '}';
    }
}
