## Overview

This document outlines the conventions for the minimal frontend components of the Reverse Proxy Auth Gateway, specifically the Flask-based login page.

## Architecture

* **Framework:** Server-side rendering using Flask and the Jinja2 templating engine.
* **Structure:** A single primary HTML template (`login.html`) served by the Flask application.

## Components

* **Login Form (`login.html`):**
    * Standard HTML form containing fields for username and password.
    * Submit button.
    * Area to display error messages (populated by Flask/Jinja2 context).
    * Should use semantic HTML elements (`<form>`, `<label>`, `<input>`, `<button>`).

## Styling

* **Approach:** Minimal custom CSS. No large CSS frameworks (like Bootstrap or Tailwind) are necessary unless specifically desired for minor utilities.
* **File:** A single `style.css` file linked in the `login.html` template.
* **Principles:** Focus on clarity, usability, and basic branding. Ensure form elements are easily identifiable and usable.
* **Responsiveness:** Basic responsive design (adapting to different screen sizes) is recommended but not strictly required for the initial version.

## State Management

* Not applicable on the frontend. All state (authentication status, error messages) is managed by the Flask backend and passed to the template during rendering.

## JavaScript

* Minimal to none required. Avoid complex client-side logic. Basic form validation (e.g., required fields) can be handled by HTML5 attributes.

## Accessibility (A11y)

* Ensure proper use of `<label>` elements associated with their respective `<input>` fields.
* Use appropriate ARIA attributes if needed, although standard HTML should suffice for this simple form.
* Ensure sufficient color contrast for text and UI elements.
* Ensure keyboard navigability of the form.