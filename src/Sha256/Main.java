package Sha256;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter message to hash with SHA256:");
        String message = sc.nextLine();
        System.out.println("After hashing: " + SHA256.hash(message));
    }
}
