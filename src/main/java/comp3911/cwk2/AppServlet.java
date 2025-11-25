package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY   = "select password_salt, password_hash from user where username=?";
  private static final String SEARCH_QUERY = "select * from patient where surname=? collate nocase";

  private static final String CSRF_COOKIE_NAME = "CSRF-TOKEN";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;
  private final PasswordHasher hasher = new PasswordHasher();

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
    migratePasswordToHash();
  }

  void migratePasswordToHash() {
    try (Statement queryStatement = database.createStatement()) {
      ResultSet results = queryStatement.executeQuery(
          "SELECT id, password, password_hash, password_salt FROM user");
      while (results.next()) {
        String id = results.getString("id");
        String passwordHash = results.getString("password_hash");
        String passwordSalt = results.getString("password_salt");

        if (passwordHash == null || passwordSalt == null) {
          byte[] rawPasswordSalt = hasher.generateSalt();
          passwordHash = hasher.hash(results.getString("password"), rawPasswordSalt);

          PreparedStatement updateStatement = database.prepareStatement(
              "UPDATE user SET password_hash=?, password_salt=? WHERE id=?");
          updateStatement.setString(1, passwordHash);
          updateStatement.setString(2, hasher.encodeSalt(rawPasswordSalt));
          updateStatement.setString(3, id);
          updateStatement.executeUpdate();
        }
      }
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    } catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    } catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      // --- CSRF double-submit: reuse existing cookie if present, otherwise create one ---
      String csrfToken = null;

      Cookie[] cookies = request.getCookies();
      if (cookies != null) {
        for (Cookie cookie : cookies) {
          if (CSRF_COOKIE_NAME.equals(cookie.getName())) {
            csrfToken = cookie.getValue();
            break;
          }
        }
      }

      // no existing cookie -> generate a new token and send it
      if (csrfToken == null) {
        csrfToken = UUID.randomUUID().toString();
        Cookie csrfCookie = new Cookie(CSRF_COOKIE_NAME, csrfToken);

        String contextPath = request.getContextPath();
        if (contextPath == null || contextPath.isEmpty()) {
          csrfCookie.setPath("/");
        } else {
          csrfCookie.setPath(contextPath);
        }

        response.addCookie(csrfCookie);
      }

      Map<String, Object> model = new HashMap<>();
      model.put("csrfToken", csrfToken);
      // --- end CSRF setup ---

      Template template = fm.getTemplate("login.html");
      template.process(model, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname  = request.getParameter("surname");

    // --- CSRF double-submit validation, compare cookie vs form field ---
    String cookieToken = null;
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (CSRF_COOKIE_NAME.equals(cookie.getName())) {
          cookieToken = cookie.getValue();
          break;
        }
      }
    }
    String formToken = request.getParameter("csrfToken");

    if (cookieToken == null || formToken == null || !cookieToken.equals(formToken)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    // --- end CSRF validation ---

    try {
      if (authenticated(username, password)) {
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      } else {
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private boolean authenticated(String username, String password) throws SQLException {
    try (PreparedStatement stmt = database.prepareStatement(AUTH_QUERY)) {
      stmt.setString(1, username);
      ResultSet results = stmt.executeQuery();

      if (!results.next()) {
        return false;
      }

      byte[] salt = hasher.decodeSalt(results.getString("password_salt"));
      String hash = hasher.hash(password, salt);

      return hash.equals(results.getString("password_hash"));
    }
  }

  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    try (PreparedStatement stmt = database.prepareStatement(SEARCH_QUERY)) {
      stmt.setString(1, surname);
      ResultSet results = stmt.executeQuery();
      while (results.next()) {
        Record rec = new Record();
        rec.setSurname(results.getString(2));
        rec.setForename(results.getString(3));
        rec.setAddress(results.getString(4));
        rec.setDateOfBirth(results.getString(5));
        rec.setDoctorId(results.getString(6));
        rec.setDiagnosis(results.getString(7));
        records.add(rec);
      }
    }
    return records;
  }
}
