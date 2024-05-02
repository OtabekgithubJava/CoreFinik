import { Component } from '@angular/core';
import { AuthService } from '../../Services/auth.service';

@Component({
  selector: 'app-main-navbar',
  templateUrl: './main-navbar.component.html',
  styleUrl: './main-navbar.component.scss'
})
export class MainNavbarComponent {
  constructor(private authService: AuthService) {}

  logout() {
    this.authService.logout();
    console.log('logged out');
  }
}
