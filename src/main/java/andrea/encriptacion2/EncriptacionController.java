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

/**
 * Controlador para la interfaz de encriptación y desencriptación de textos utilizando los algoritmos AES y DES.
 */
public class EncriptacionController {


    @FXML
    private TextField textoEncriptar;
    @FXML
    private TextArea textAreaTextoEncriptado;
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


    private String contrasenyaEncriptada;

    /**
     * Inicializa los eventos de los botones al iniciar la interfaz.
     */
    @FXML
    public void initialize() {

        botonEncriptarAES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() && textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            } else if (textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposIncorrectos();
                return;
            }

            String texto = textoEncriptar.getText();
            String contrasenya = textIntroductirContrasenya.getText();
            String encripTexto;
            try {
                encripTexto = encryptAES(texto, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textAreaTextoEncriptado.setText("Texto encriptado con AES: " + encripTexto);
        });

        /**
         * Botón que desencripta un texto con AES
         */
        botonDesencriptarAES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() || textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String textoEncriptado = textAreaTextoEncriptado.getText().replace("Texto encriptado con AES: ", "");
            String contrasenya = textIntroductirContrasenya.getText();
            String textoDesencriptado ;
            try {
                textoDesencriptado = decryptAES(textoEncriptado, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textAreaTextoEncriptado.appendText("\nTexto desencriptado con AES: " + textoDesencriptado);
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
            String texto = textoEncriptar.getText();
            String contrasenya = textIntroductirContrasenya.getText();
            String textoEncriptado;
            try {
                textoEncriptado = encryptDES(texto, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textAreaTextoEncriptado.appendText("\nTexto encriptado con DES: " + textoEncriptado);
        });

        /**
         * Botón que desencripta un texto con DES
         */
        botonDesencriptarDES.setOnAction(e -> {
            if (textoEncriptar.getText().isEmpty() || textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String textoEncriptado = textAreaTextoEncriptado.getText().replace("Texto encriptado con DES: ", "");
            textoEncriptado = textoEncriptado.split("\n")[textoEncriptado.split("\n").length - 1];
            String contrasenya = textIntroductirContrasenya.getText();
            textoEncriptado = textoEncriptado.replaceAll("\\s", "");
            String textoDesencriptado = null;
            try {
                textoDesencriptado  = decryptDES(textoEncriptado, contrasenya);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }
            textAreaTextoEncriptado.appendText("\nTexto desencriptado con DES: " + textoDesencriptado );
        });

        /**
         * Botón que encripta una contraseña
         */
        botonContrasenya.setOnAction(e -> {
            if (textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String contrasenya = textIntroductirContrasenya.getText();
            contrasenyaEncriptada = BCrypt.hashpw(contrasenya, BCrypt.gensalt());
            texContrasenya.setText("Contraseña encriptada: " + contrasenyaEncriptada);
        });
        /**
         * Botón que comprueba si una contraseña es correcta
         */
        botonComprobarContrasenya.setOnAction(e -> {
            if (contrasenyaEncriptada == null || textIntroductirContrasenya.getText().isEmpty()) {
                alertaCamposVacios();
                return;
            }
            String checkContra = textIntroductirContrasenya.getText();
            boolean esCorrecta = BCrypt.checkpw(checkContra, contrasenyaEncriptada);
            texContrasenya.appendText("\n¿Contraseña correcta? " + esCorrecta);
            if (esCorrecta) {
                alertaContrasenyaCorrecta();
            } else {
                alertaContrasenyaIncorrecta();
            }

        });
        /**
         * Botón que reestablece los campos
         */
        reestablecer.setOnAction(e -> {
            textoEncriptar.clear();
            textAreaTextoEncriptado.clear();
            textIntroductirContrasenya.clear();
            texContrasenya.clear();
        });
    }


    /**
     * Genera una clave secreta basada en una contraseña y el algoritmo de cifrado.
     *
     * @param contrasenya La contraseña utilizada para generar la clave.
     * @param algoritmo   El algoritmo de cifrado (AES o DES).
     * @return Una clave secreta generada a partir de la contraseña.
     * @throws NoSuchAlgorithmException    Si el algoritmo de hash no está disponible.
     * @throws UnsupportedEncodingException Si la codificación no es soportada.
     */
    private SecretKey obtenerContrasenya(String contrasenya, String algoritmo) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] clave = contrasenya.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        clave = sha.digest(clave);
        clave = Arrays.copyOf(clave, algoritmo.equals("AES") ? 16 : 8); //AES  16 bytes, DES uses 8 bytes
        return new SecretKeySpec(clave, algoritmo);
    }


    /**
     * Encripta un texto utilizando el algoritmo AES.
     *
     * @param datos      Texto a encriptar.
     * @param contrasenya Contraseña utilizada para generar la clave de encriptación.
     * @return Texto encriptado en formato Base64.
     * @throws UnsupportedEncodingException Si la codificación no es soportada.
     * @throws NoSuchAlgorithmException Si el algoritmo de hash no está disponible.
     * @throws NoSuchPaddingException Si el relleno no está disponible.
     * @throws InvalidKeyException Si la clave no es válida.
     * @throws IllegalBlockSizeException Si el tamaño del bloque no es válido.
     * @throws BadPaddingException Si el relleno no es válido.
     */
    private String encryptAES(String datos, String contrasenya) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            SecretKey claveAES = obtenerContrasenya(contrasenya, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, claveAES);
            byte[] datosEncriptados = cipher.doFinal(datos.getBytes());
            return Base64.getEncoder().encodeToString(datosEncriptados);
    }

    /**
     * Desencripta un texto utilizando el algoritmo AES.
     *
     * @param datosEncriptados Texto encriptado en formato Base64.
     * @param contrasenya       Contraseña utilizada para generar la clave de desencriptación.
     * @return Texto desencriptado.
     * @throws UnsupportedEncodingException Si la codificación no es soportada.
     * @throws NoSuchAlgorithmException Si el algoritmo de hash no está disponible.
     * @throws NoSuchPaddingException Si el relleno no está disponible.
     * @throws InvalidKeyException Si la clave no es válida.
     * @throws IllegalBlockSizeException Si el tamaño del bloque no es válido.
     * @throws BadPaddingException Si el relleno no es válido.
     */

    private String decryptAES(String datosEncriptados, String contrasenya) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            SecretKey claveAES = obtenerContrasenya(contrasenya, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, claveAES);
            byte[] datosDesencriptados = cipher.doFinal(Base64.getDecoder().decode(datosEncriptados));
            return new String(datosDesencriptados);

    }

    /**
     * Método que encripta un texto con DES
     *
     * @param datos
     * @param contrasenya contraseña con la que se encripta
     * @return texto encriptado
     * @throws UnsupportedEncodingException Si la codificación no es soportada.
     * @throws NoSuchAlgorithmException Si el algoritmo de hash no está disponible.
     * @throws NoSuchPaddingException Si el relleno no está disponible.
     * @throws InvalidKeyException Si la clave no es válida.
     * @throws IllegalBlockSizeException Si el tamaño del bloque no es válido.
     * @throws BadPaddingException Si el relleno no es válido.
     */
    private String encryptDES(String datos, String contrasenya) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            SecretKey desKey = obtenerContrasenya(contrasenya, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, desKey);
            byte[] datosEncriptados = cipher.doFinal(datos.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(datosEncriptados);

    }

    /**
     * Método que desencripta un texto con DES
     *
     * @param datosEncriptados texto encriptado
     * @param contrasenya contraseña con la que se desencripta
     * @return texto desencriptado
     * @throws UnsupportedEncodingException Si la codificación no es soportada.
     * @throws NoSuchAlgorithmException Si el algoritmo de hash no está disponible.
     * @throws NoSuchPaddingException Si el relleno no está disponible.
     * @throws InvalidKeyException Si la clave no es válida.
     * @throws IllegalBlockSizeException Si el tamaño del bloque no es válido.
     * @throws BadPaddingException Si el relleno no es válido.
     */
    private String decryptDES(String datosEncriptados, String contrasenya) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            SecretKey desKey = obtenerContrasenya(contrasenya, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            byte[] datosDecodificados = Base64.getDecoder().decode(datosEncriptados);
            byte[] datosDesencriptados = cipher.doFinal(datosDecodificados);
            return new String(datosDesencriptados, StandardCharsets.UTF_8);
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

    /**
     * generar alerta para contraseña correcta
     */
    public void alertaContrasenyaCorrecta(){
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Información");
        alert.setHeaderText("Contraseña correcta");
        alert.setContentText("La contraseña es correcta");
        alert.showAndWait();
    }

    /**
     * generar alerta para contraseña incorrecta
     */
    public void alertaContrasenyaIncorrecta(){
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText("Contraseña incorrecta");
        alert.setContentText("La contraseña es incorrecta");
        alert.showAndWait();
    }

}
