package regex;

import java.util.ArrayList;
import java.util.HashSet;
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
    // enum lookaroundType {
    //     Pos,
    //     Neg,
    //     Behind,
    //     NotBehind
    // }

    public Type type;
    public Set<Integer> charSet;
    public ArrayList<Path> lookaroundPath;
    private Analyzer.lookaroundType lookaroundType;
    public boundType boundType;

    public PathNode(Set<Integer> charSet) {
        this.type = Type.set;
        this.charSet = charSet;
    }

    public PathNode(ArrayList<Path> lookaroundPath, Analyzer.lookaroundType lookaroundType) {
        this.type = Type.lookaround;
        this.lookaroundPath = lookaroundPath;
        this.lookaroundType = lookaroundType;
    }

    public PathNode(boundType boundType) {
        this.type = Type.bound;
        this.boundType = boundType;
    }

    public PathNode(PathNode node) {
        this.type = node.type;
        this.charSet = new HashSet<>(node.charSet);
        this.lookaroundPath = node.lookaroundPath;
        this.lookaroundType = node.lookaroundType;
        this.boundType = node.boundType;
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

    public Analyzer.lookaroundType getLookaroundType() {
        return lookaroundType;
    }

    public ArrayList<Path> getLookaroundPath() {
        return lookaroundPath;
    }

    public Set<Integer> getCharSet() {
        return charSet;
    }

    public void setCharSet(Set<Integer> tmpSet) {
        this.charSet = tmpSet;
    }
}
