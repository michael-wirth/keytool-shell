package com.example;

import ch.codeblock.qrinvoice.util.CreditorReferenceUtils;
import ch.codeblock.qrinvoice.util.IbanUtils;
import ch.codeblock.qrinvoice.util.QRReferenceUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class QR {

    @Test
    public void isValidIBAN() {
        assertThat(IbanUtils.isValidIBAN("CH1430043293262585722", true)).isTrue();
    }

    @Test
    public void isValidCreditorReference() {
        assertThat(CreditorReferenceUtils.isValidCreditorReference("RF471263")).isTrue();
    }

    @Test
    public void isValidQrReference() {
        assertThat(QRReferenceUtils.isValidQrReference("210000000003139471430009017")).isTrue();
    }
}
