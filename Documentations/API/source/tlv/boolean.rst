Boolean
=======
Definition
^^^^^^^^^^
As shown in the figure :numref:`tlv_boolean` below, a **boolean** is encoded with:

 -  *Type* is the name of the boolean to enable.
 -  *Length* always equals 0.
 -  *Value* is not present.


.. figure:: figures/tlv_boolean.png
   :align: center
   :name: tlv_boolean

   TLV boolean data


Defining a TLV boolean corresponds to set the boolean named by the type to *True*.
A boolean can't be set to *False* explicitly in TLV. In other words, to set a
boolean to *False*, it must not be defined in the TLV.

If the length is not 0, an error is returned.

Example
^^^^^^^
The :numref:`tlv_boolean_example` is the coding of the boolean attribute
named *PERSISTENT*. When present in the operation attribute lists, the
key persistency is enabled.

.. table:: Example of TLV boolean
   :name: tlv_boolean_example
   :align: left
   :widths: 8 77 15
   :width: 100%
   :class: wrap-table

   +----------+--------------------------------------------------------+------------+
   |          | **Type**                                               | **Length** |
   +==========+========================================================+============+
   | **Data** | PERSISTENT                                             | 0          |
   +----------+--------------------------------------------------------+------------+
   | **Hex**  | 0x50 0x45 0x52 0x53 0x49 0x53 0x54 0x45 0x4E 0x54 0x00 | 0x00 0x00  |
   +----------+--------------------------------------------------------+------------+
