package sslSocket;

import java.awt.Color;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class AttributeTest extends JTextPane {
    SimpleAttributeSet attributeSet;
  
    public AttributeTest() {
        //create the SimpleAttributeSet
        attributeSet = new SimpleAttributeSet();
    }
  
    public void addString(int fontSize,
            Color foregroundColor,
            Color backgroundColor,
            boolean isBold,
            boolean isItalic,
            int alignment,
            String str) {
        //add the attributes to the SimpleAttributeSet
        StyleConstants.setFontSize(attributeSet, fontSize);
        StyleConstants.setForeground(attributeSet, foregroundColor);
        StyleConstants.setBackground(attributeSet, backgroundColor);
        StyleConstants.setBold(attributeSet, isBold);
        StyleConstants.setItalic(attributeSet, isItalic);
        StyleConstants.setAlignment(attributeSet, alignment);
      
        //set the attribute to the StyledDocument
        int len = this.getText().length();     
        StyledDocument sDoc = this.getStyledDocument();
        sDoc.setCharacterAttributes(len, str.length(), attributeSet, false);

        // Or using the following two lines of code to replace the above two lines of code
       // this.setCaretPosition(len);
      //  this.setCharacterAttributes(attributeSet, false);
    
       //insert the string to the JTextPane
        this.replaceSelection(str);
    }
  
    public static void main(String[] args){
        String[] strs = {"The Third Line\n",
                         "The Second Line\n",
                         "The First Line\n",
                         "Style Test Result\n"
                         };
        AttributeTest test = new AttributeTest();
        for (int i=0; i<strs.length; i++) {
            if (i == 3){
                test.addString(14, Color.blue, Color.LIGHT_GRAY, true, false, StyleConstants.ALIGN_RIGHT, strs[i]);
            } else if (i == 2){
                test.addString(11, Color.red, Color.GREEN, false, true, StyleConstants.ALIGN_RIGHT, strs[i]);
            } else if (i == 1) {
                test.addString(11, Color.orange, Color.LIGHT_GRAY, false, false, StyleConstants.ALIGN_LEFT, strs[i]);
            } else {
                test.addString(11, Color.black, Color.CYAN, false, false, StyleConstants.ALIGN_LEFT, strs[i]);
            }
        }
        test.setBackground(Color.yellow);
        JFrame f = new JFrame("Style Test");
        f.setContentPane(new JScrollPane(test));
        f.setSize(500, 300);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.setVisible(true);
    }
}