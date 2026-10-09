package com.urlverifier.check;

public record Finding(String check, int score, Severity severity, String message) {
    public enum Severity { OK, INFO, LOW, MEDIUM, HIGH }

    public static Finding ok(String check, String message) { return new Finding(check, 0, Severity.OK, message); }
    public static Finding info(String check, String message) { return new Finding(check, 0, Severity.INFO, message); }
}
