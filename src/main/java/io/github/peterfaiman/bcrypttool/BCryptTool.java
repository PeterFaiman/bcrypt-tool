package io.github.peterfaiman.bcrypttool;

import org.apache.commons.cli.*;
import org.mindrot.jbcrypt.BCrypt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class BCryptTool {
  public static void main(String[] args) {
    Options options = new Options();
    options.addOption("h", "help", false, "print this help text");
    options.addOption("r", "rounds", true, "log rounds to use when generating the salt");
    options.addOption("q", "quiet", false, "when checking passwords, do not print the result");

    CommandLineParser parser = new PosixParser();
    CommandLine cmd = null;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.err.println("ERROR[bcrypt]: " + e.getMessage());
      System.exit(1);
    }

    if (cmd.hasOption("h")) {
      new HelpFormatter().printHelp("bcrypt [options] <password> [hash]\n", options);
      return;
    }

    int rounds = 10;
    if (cmd.hasOption("r")) {
      String r = cmd.getOptionValue("r");
      try {
        rounds = Integer.parseInt(r);
      } catch (NumberFormatException e) {
        System.err.println("ERROR[bcrypt]: Bad number of rounds");
        System.exit(1);
      }

      /* max is 31 in 0.3, but 30 in 0.4 fixing an integer overflow bug */
      if (rounds < 4 || rounds > 30) {
        System.err.println("ERROR[bcrypt]: Bad number of rounds");
        System.exit(1);
      }
    }

    String[] remainingArgs = cmd.getArgs();
    if (remainingArgs.length == 1) { /* 1 arg -> hash */
      String salt;
      try {
        salt = BCrypt.gensalt(rounds, SecureRandom.getInstanceStrong());
      } catch (NoSuchAlgorithmException e) {
        System.err.println("WARNING[bcrypt]: No strong secure random algorithm found");
        salt = BCrypt.gensalt(rounds);
      }

      try {
        System.out.println(BCrypt.hashpw(remainingArgs[0], salt));
      } catch (IllegalArgumentException e) {
        System.err.println("ERROR[bcrypt]: " + e.getMessage());
        System.exit(1);
      }
    }
    else if (remainingArgs.length == 2) { /* 2 args -> check */
      boolean ok = false;
      try {
        ok = BCrypt.checkpw(remainingArgs[0], remainingArgs[1]);
      } catch (IllegalArgumentException e) {
        System.err.println("ERROR[bcrypt]: " + e.getMessage());
        System.exit(1);
      }
      if (!cmd.hasOption("q")) {
        System.out.println(ok ? "OK" : "FAIL");
      }
      System.exit(ok ? 0 : 1);
    }
    else {
      System.err.println("ERROR[bcrypt]: Only a password or a password and hash may be provided");
      System.exit(1);
    }
  }
}
