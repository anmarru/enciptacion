module andrea.encriptacion2 {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires jbcrypt;

    opens andrea.encriptacion2 to javafx.fxml;
    exports andrea.encriptacion2;
}