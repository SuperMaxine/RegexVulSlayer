package regex;

import java.util.ArrayList;
import java.util.Set;

public class PathNode {
    enum Type {
        set,
        lookaround,
        bound
    }
    enum boundType {
        lower,
        upper
    }
    enum lookaroundType {
        Pos,
        Neg,
        Behind,
        NotBehind
    }

    public Type type;
    public Set<Integer> charSet;
    public ArrayList<Set<Integer>> lookaroundPath;
    private lookaroundType lookaroundType;
    public boundType boundType;

    public PathNode(Set<Integer> charSet) {
        this.type = Type.set;
        this.charSet = charSet;
    }

    public PathNode(ArrayList<Set<Integer>> lookaroundPath, lookaroundType lookaroundType) {
        this.type = Type.lookaround;
        this.lookaroundPath = lookaroundPath;
        this.lookaroundType = lookaroundType;
    }

    public PathNode(boundType boundType) {
        this.type = Type.bound;
        this.boundType = boundType;
    }
    public boolean isSet() {
        return type == Type.set;
    }

    public boolean isLookaround() {
        return type == Type.lookaround;
    }

    public boolean isBound() {
        return type == Type.bound;
    }

    public boundType getBoundType() {
        return boundType;
    }

    public lookaroundType getLookaroundType() {
        return lookaroundType;
    }

    public ArrayList<Set<Integer>> getLookaroundPath() {
        return lookaroundPath;
    }

    public Set<Integer> getCharSet() {
        return charSet;
    }
}
