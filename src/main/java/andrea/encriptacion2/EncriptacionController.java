package andrea.encriptacion2;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class EncriptacionController {


    @FXML
    private TextField textoEncriptar;
    @FXML
    private TextArea textoEncriptado;
    @FXML
    private Button botonEncriptarAES;
    @FXML
    private Button botonDesencriptarAES;
    @FXML
    private Button botonEncriptarDES;
    @FXML
    private Button botonDesencriptarDES;
    @FXML
    private TextArea texContrasenya;
    @FXML
    private Button botonContrasenya;
    @FXML
    private Button botonComprobarContrasenya;
    @FXML
    private TextField textIntroductirContrasenya;
    @FXML
    private Button reestablecer;

    /**
     * Variable que almacena la contraseña encriptada
     */
    private String hashedPassword;

    /**
     * Método que se ejecuta al iniciar la aplicación
     */
    @FXML
    public void initialize() {
        /**
         * Botón que encripta un texto con AES
         */
        botonEncriptarAES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() && textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            } else if (textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposIncorrectos();
                return;
            }

            String text = textoEncriptar.getText();
            String contrasenya = textIntroductirContrasenya.getText();
            String encryptedText = null;
            try {
                encryptedText = encryptAES(text, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textoEncriptado.setText("Texto encriptado con AES: " + encryptedText);
        });

        /**
         * Botón que desencripta un texto con AES
         */
        botonDesencriptarAES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() || textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String encryptedText = textoEncriptado.getText().replace("Texto encriptado con AES: ", "");
            String contrasenya = textIntroductirContrasenya.getText();
            String decryptedText = null;
            try {
                decryptedText = decryptAES(encryptedText, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textoEncriptado.appendText("\nTexto desencriptado con AES: " + decryptedText);
        });

        /**
         * Botón que encripta un texto con DES
         */
        botonEncriptarDES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() && textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            } else if (textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposIncorrectos();
                return;
            }
            String text = textoEncriptar.getText();
            String contrasenya = textIntroductirContrasenya.getText();
            String encryptedText = null;
            try {
                encryptedText = encryptDES(text, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textoEncriptado.appendText("\nTexto encriptado con DES: " + encryptedText);
        });

        /**
         * Botón que desencripta un texto con DES
         */
        botonDesencriptarDES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() || textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String encryptedText = textoEncriptado.getText().replace("Texto encriptado con DES: ", "");
            String contrasenya = textIntroductirContrasenya.getText();
            encryptedText = encryptedText.replaceAll("\\s", "");
            String decryptedText = null;
            try {
                decryptedText = decryptDES(encryptedText, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textoEncriptado.appendText("\nTexto desencriptado con DES: " + decryptedText);
        });

        /**
         * Botón que encripta una contraseña y la muestra en el TextArea correspondiente
         */
        botonContrasenya.setOnAction(e -> {
            if (textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String password = textIntroductirContrasenya.getText();
            hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
            texContrasenya.setText("Contraseña encriptada: " + hashedPassword);
        });
        /**
         * Botón que comprueba si una contraseña es correcta
         */
        botonComprobarContrasenya.setOnAction(e -> {
            if (hashedPassword == null || textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String checkContra = textIntroductirContrasenya.getText();
            boolean esCorrecta = BCrypt.checkpw(checkContra, hashedPassword);
            texContrasenya.appendText("\n¿Contraseña correcta? " + esCorrecta);
            if (esCorrecta) {
                alertaContrasenyaCorrecta();
            } else {
                alertaContrasenyaIncorrecta();
            }

        });

        reestablecer.setOnAction(e -> {
            textoEncriptar.clear();
            textoEncriptado.clear();
            textIntroductirContrasenya.clear();
            texContrasenya.clear();
        });
    }


    /**
     * Método que genera una clave para encriptar y desencriptar
     */
    private SecretKey obtenerContrasenya(String password, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] key = password.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, algorithm.equals("AES") ? 16 : 8); //AES  16 bytes, DES uses 8 bytes
        return new SecretKeySpec(key, algorithm);
    }


    /**
     * Método que encripta un texto con AES
     */
    private String encryptAES(String data, String password) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            SecretKey aesKey = obtenerContrasenya(password, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);


    }

    /**
     * Método que desencripta un texto con AES
     */
    private String decryptAES(String encryptedData, String password) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            SecretKey aesKey = obtenerContrasenya(password, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData);

    }

    /**
     * Método que encripta un texto con DES
     *
     * @param data
     * @param password
     */
    private String encryptDES(String data, String password) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            SecretKey desKey = obtenerContrasenya(password, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, desKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedData);

    }

    /**
     * Método que desencripta un texto con DES
     *
     * @param encryptedData
     * @param password
     */
    private String decryptDES(String encryptedData, String password) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            SecretKey desKey = obtenerContrasenya(password, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            byte[] decodedData = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * generar alerta para campos incorrectos
     */
    public void alertaCamposIncorrectos() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText("Campos incorrectos");
        alert.setContentText("Por favor, rellene todos los campos correctamente");
        alert.showAndWait();
    }

    /**
     * generar alerta para campos vacíos
     */
    public void alertaCamposVacios() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText("Campos vacíos");
        alert.setContentText("Por favor, rellene todos los campos");
        alert.showAndWait();
    }

    public void alertaContrasenyaCorrecta(){
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Información");
        alert.setHeaderText("Contraseña correcta");
        alert.setContentText("La contraseña es correcta");
        alert.showAndWait();
    }

    public void alertaContrasenyaIncorrecta(){
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText("Contraseña incorrecta");
        alert.setContentText("La contraseña es incorrecta");
        alert.showAndWait();
    }

}
