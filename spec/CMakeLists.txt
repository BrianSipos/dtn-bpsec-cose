cmake_minimum_required(VERSION 3.10)
project(
    draft-sipos-dtn-bpsec-cose
    LANGUAGES
)

set(DRAFT_NAME "${PROJECT_NAME}")

find_program(XML2RFC xml2rfc)
if(NOT XML2RFC)
    message(FATAL_ERROR "Program xml2rfc not found")
endif()
find_program(XMLSTARLET xmlstarlet)
if(NOT XMLSTARLET)
    message(FATAL_ERROR "Program xmlstarlet not found")
endif()
find_program(ASPELL aspell)
if(NOT ASPELL)
    message(FATAL_ERROR "Program aspell not found")
endif()
find_program(PYTHON python)
if(NOT PYTHON)
    message(FATAL_ERROR "Program python not found")
endif()
set(SPLIT_ARTWORK "${CMAKE_CURRENT_SOURCE_DIR}/split_artwork.py")

set(DRAFT_NAME_XML "${CMAKE_CURRENT_SOURCE_DIR}/${DRAFT_NAME}.xml")
set(DRAFT_NAME_TXT "${DRAFT_NAME}.txt")
set(DRAFT_NAME_HTML "${DRAFT_NAME}.html")
add_custom_command(
    OUTPUT "${DRAFT_NAME_TXT}"
    DEPENDS "${DRAFT_NAME_XML}"
    COMMAND ${XML2RFC} --text -o "${DRAFT_NAME_TXT}" "${DRAFT_NAME_XML}"
)
add_custom_command(
    OUTPUT "${DRAFT_NAME_HTML}"
    DEPENDS "${DRAFT_NAME_XML}"
    COMMAND ${XML2RFC} --html -o "${DRAFT_NAME_HTML}" "${DRAFT_NAME_XML}"
)

set(DICTIONARY_TXT "${CMAKE_CURRENT_SOURCE_DIR}/dictionary.txt")
set(SPELLCHECK_XSL "${CMAKE_CURRENT_SOURCE_DIR}/spellcheck.xsl")
set(MISSPELLING_TXT "misspelling.txt")
add_custom_command(
    OUTPUT "dictionary.cwl"
    DEPENDS "${DICTIONARY_TXT}"
    COMMAND cat "${DICTIONARY_TXT}" | 
        ${ASPELL} --lang=en create master "./dictionary.cwl"
)
add_custom_command(
    OUTPUT "${MISSPELLING_TXT}"
    DEPENDS "${DRAFT_NAME_XML}" "${SPELLCHECK_XSL}" "dictionary.cwl"
    COMMAND ${XMLSTARLET} tr "${SPELLCHECK_XSL}" "${DRAFT_NAME_XML}" | 
        ${ASPELL} --mode=sgml --lang=EN_US --extra-dicts=./dictionary.cwl list | 
        sort | uniq > "${MISSPELLING_TXT}"
)

find_program(CBORVERIFY diag2cbor.rb)
if(CBORVERIFY)
    set(CBORERRORS_TXT "cborerrors.txt")
    add_custom_command(
        OUTPUT "${CBORERRORS_TXT}"
        DEPENDS "${DRAFT_NAME_XML}" "${SPLIT_ARTWORK}"
        COMMAND ${PYTHON} "${SPLIT_ARTWORK}" "${DRAFT_NAME_XML}" '//artwork[@type="cbor"]' "${CBORVERIFY}" >/dev/null 2>"${CBORERRORS_TXT}"
    )
    add_custom_target(
        cborerrors ALL
        DEPENDS "${CBORERRORS_TXT}"
    )
endif()

add_custom_target(
    specs ALL
    DEPENDS "${DRAFT_NAME_TXT}" "${DRAFT_NAME_HTML}" "${MISSPELLING_TXT}"
)
