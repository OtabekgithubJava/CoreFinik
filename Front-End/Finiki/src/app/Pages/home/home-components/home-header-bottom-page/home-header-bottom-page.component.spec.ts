import { ComponentFixture, TestBed } from '@angular/core/testing';

import { HomeHeaderBottomPageComponent } from './home-header-bottom-page.component';

describe('HomeHeaderBottomPageComponent', () => {
  let component: HomeHeaderBottomPageComponent;
  let fixture: ComponentFixture<HomeHeaderBottomPageComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [HomeHeaderBottomPageComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(HomeHeaderBottomPageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
