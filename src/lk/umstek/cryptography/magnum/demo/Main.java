package lk.umstek.cryptography.magnum.demo;

import lk.umstek.cryptography.magnum.Magnum;

import java.io.*;
import java.util.Arrays;
import java.util.Scanner;

@SuppressWarnings("Duplicates")
public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter file path to encrypt/decrypt: ");
        String path = scanner.nextLine();

        System.out.println("Enter password: ");
        String password = scanner.nextLine();

        System.out.println("[E]ncrypt or [D]ecrypt?");
        String action = scanner.nextLine();

        if ("e".equals(action.toLowerCase())) {
            encrypt(path, password);
        } else if ("d".equals(action.toLowerCase())) {
            decrypt(path, password);
        } else {
            System.out.println("Unknown operation: " + "'" + action + "'");
        }
    }

    private static void encrypt(String path, String password) {
        byte[] fileBytes = new byte[0];
        try {
            File file = new File(path);
            fileBytes = new byte[(int) file.length()];
            FileInputStream inputStream = new FileInputStream(file);
            final int bytesRead = inputStream.read(fileBytes);
            inputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] passwordBytes = password.getBytes();

        final byte[][] encrypted = Magnum.encrypt(passwordBytes, fileBytes);

        byte[] writeToFile = new byte[encrypted[0].length + encrypted[1].length];
        System.arraycopy(encrypted[0], 0, writeToFile, 0, encrypted[0].length);
        System.arraycopy(encrypted[1], 0, writeToFile, encrypted[0].length, encrypted[1].length);
        try {
            FileOutputStream outputStream = new FileOutputStream(path + ".enc");
            outputStream.write(writeToFile);
            outputStream.flush();
            outputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void decrypt(String path, String password) {
        byte[] fileBytes = new byte[0];
        try {
            File file = new File(path);
            fileBytes = new byte[(int) file.length()];
            FileInputStream inputStream = new FileInputStream(file);
            final int bytesRead = inputStream.read(fileBytes);
            inputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] passwordBytes = password.getBytes();
        byte[] iv = Arrays.copyOfRange(fileBytes, 0, 32);
        byte[] data = Arrays.copyOfRange(fileBytes, 32, fileBytes.length);

        final byte[] decrypted = Magnum.decrypt(iv, passwordBytes, data);

        try {
            FileOutputStream outputStream = new FileOutputStream(path + ".dec");
            outputStream.write(decrypted);
            outputStream.flush();
            outputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
